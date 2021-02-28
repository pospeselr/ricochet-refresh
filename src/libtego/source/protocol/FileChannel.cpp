/* Ricochet Refresh - https://ricochetrefresh.net/
 * Copyright (C) 2020, Blueprint For Free Speech <ricochet@blueprintforfreespeech.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 *    * Neither the names of the copyright owners nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "FileChannel.h"
#include "Channel_p.h"
#include "Connection.h"
#include "utils/SecureRNG.h"
#include "utils/Useful.h"

#include "context.hpp"
#include "error.hpp"
#include "globals.hpp"
#include "file_hash.hpp"
using tego::g_globals;

using namespace Protocol;

static void logTransferStats(qint64 bytes, std::chrono::time_point<std::chrono::system_clock> beginTime)
{
    const auto kilobytes = bytes / 1024.0;
    const auto seconds = std::chrono::duration_cast<std::chrono::duration<double>>( std::chrono::system_clock::now() - beginTime).count();

    logger::println("Transfer Complete: {{ size : {} kilobytes, duration : {} seconds, rate : {} kilobytes / second}}", kilobytes, seconds, kilobytes / seconds);
};

// Outgoing Transfer Record

FileChannel::outgoing_transfer_record::outgoing_transfer_record(
    file_id_t id,
    const std::string& filePath,
    qint64 fileSize)
: id(id)
, size(fileSize)
, offset(0)
, stream(filePath, std::ios::in | std::ios::binary)
{ }

// Incoming Transfer Record

FileChannel::incoming_transfer_record::incoming_transfer_record(
    file_id_t id,
    qint64 fileSize,
    const std::string& fileHash)
: id(id)
, size(fileSize)
, sha3_512(fileHash)
, stream()
{ }

FileChannel::incoming_transfer_record::~incoming_transfer_record()
{
    if (this->stream.is_open())
    {
        // try our best to remove the partial file
        this->stream.close();

        // ignore error here, if incoming request succeeded then the
        // partial should no longer exist
        QFile::remove(QString::fromStdString(this->partial_dest()));
    }
}


std::string FileChannel::incoming_transfer_record::partial_dest() const
{
    return  dest + ".part";
}

void FileChannel::incoming_transfer_record::open_stream(const std::string& dest)
{
    this->dest = dest;

    // attempt to open the destination for reading and writing
    // discard previous contents
    // binary mode
    // we need to read to validate the hash after the transfer completes
    this->stream.open(this->partial_dest(), std::ios::in | std::ios::out | std::ios::trunc | std::ios::binary);
    TEGO_THROW_IF_FALSE(this->stream.is_open());
}

// File Channel

FileChannel::FileChannel(Direction direction, Connection *connection)
    : Channel(QStringLiteral("im.ricochet.file-transfer"), direction, connection)
{ }

bool FileChannel::allowInboundChannelRequest(
    const Data::Control::OpenChannel*,
    Data::Control::ChannelResult *result)
{
    if (connection()->purpose() != Connection::Purpose::KnownContact) {
        qDebug() << "Rejecting request for" << type() << "channel from connection with purpose" << int(connection()->purpose());
        result->set_common_error(Data::Control::ChannelResult::UnauthorizedError);
        return false;
    }

    if (connection()->findChannel<FileChannel>(Channel::Inbound)) {
        qDebug() << "Rejecting request for" << type() << "channel because one is already open";
        return false;
    }

    return true;
}

bool FileChannel::allowOutboundChannelRequest(
    Data::Control::OpenChannel*)
{
    if (connection()->findChannel<FileChannel>(Channel::Outbound)) {
        BUG() << "Rejecting outbound request for" << type() << "channel because one is already open on this connection";
        return false;
    }

    if (connection()->purpose() != Connection::Purpose::KnownContact) {
        BUG() << "Rejecting outbound request for" << type() << "channel for connection with unexpected purpose" << int(connection()->purpose());
        return false;
    }

    return true;
}

void FileChannel::receivePacket(const QByteArray &packet)
{
    Data::File::Packet message;
    if (!message.ParseFromArray(packet.constData(), packet.size())) {
        qWarning() << "failed to parse message on file channel";
        closeChannel();
        return;
    }

    if (message.has_file_header()) {
        handleFileHeader(message.file_header());
    } else if (message.has_file_header_ack()) {
        handleFileHeaderAck(message.file_header_ack());
    } else if (message.has_file_chunk()) {
        handleFileChunk(message.file_chunk());
    } else if (message.has_file_header_response()) {
        handleFileHeaderResponse(message.file_header_response());
    } else if (message.has_file_chunk_ack()) {
        handleFileChunkAck(message.file_chunk_ack());
    } else if (message.has_file_transfer_complete_notification()) {
        handleFileTransferCompleteNotification(message.file_transfer_complete_notification());
    } else {
        qWarning() << "Unrecognized file packet on " << type();
        closeChannel();
    }
}

void FileChannel::handleFileHeader(const Data::File::FileHeader &message)
{
    Q_ASSERT(direction() == Inbound);

    auto response = std::make_unique<Data::File::FileHeaderAck>();
    response->set_accepted(false);

    if (message.name().find("..") != std::string::npos) {
        qWarning() << "Rejected file header with name containing '..'";
    } else if (message.name().find("/") != std::string::npos) {
        qWarning() << "Rejected file header with name containing '/'";
    } else {
        const auto id = message.file_id();
        incoming_transfer_record ifr(id, message.size(), message.sha3_512());

        // TODO: change the protocol to send a byte buffer of the exact size?
        TEGO_THROW_IF_FALSE_MSG(ifr.sha3_512.size() == (tego_file_hash::STRING_SIZE - 1));
        tego_file_hash fileHash;
        fileHash.hex = ifr.sha3_512;

        // signal the file transfer request
        emit this->fileTransferRequestReceived(id, QString::fromStdString(message.name()), ifr.size, std::move(fileHash));

        incomingTransfers.insert({id, std::move(ifr)});

        response->set_file_id(id);
        response->set_accepted(true);
    }

    // finally send our ack for the header
    Data::File::Packet packet;
    packet.set_allocated_file_header_ack(response.release());
    Channel::sendMessage(packet);
}

void FileChannel::handleFileHeaderAck(const Data::File::FileHeaderAck &message)
{
    if (direction() != Outbound) {
        qWarning() << "Rejected inbound acknowledgement on an inbound file channel";
        closeChannel();
        return;
    }

    auto id = message.file_id();
    if (outgoingTransfers.contains(id))
    {
        emit this->fileTransferAcknowledged(id, message.accepted());
    } else {
        qDebug() << "Received chat acknowledgement for unknown message" << id;
    }
}

void FileChannel::handleFileHeaderResponse(const Data::File::FileHeaderResponse &message)
{
    if (direction() != Outbound) {
        qWarning() << "Rejected inbound message on inbound file channel";
        return;
    }

    const auto id = message.file_id();

    auto it = outgoingTransfers.find(id);
    if (it == outgoingTransfers.end())
    {
        qWarning() << "recieved response for a file header we never sent";
        return;
    }

    /* start the transfer at chunk 0 */
    const auto response = message.response();
    if (response == tego_attachment_response_accept)
    {
        sendNextChunk(id);
        it->second.beginTime = std::chrono::system_clock::now();
    }
    else
    {
        if (response != tego_attachment_response_reject)
        {
            qWarning() << "received unknown response for file header";
        }
        // receiver rejected our transfer request, so erase it from our records
        outgoingTransfers.erase(it);
    }

    emit this->fileTransferRequestResponded(message.file_id(), static_cast<tego_attachment_response_t>(response));
}

void FileChannel::handleFileChunk(const Data::File::FileChunk &message)
{
    auto it = incomingTransfers.find(message.file_id());
    if (it == incomingTransfers.end()) {
        qWarning() << "rejecting chunk for unknown file";
        return;
    }
    else if (message.chunk_data().size() > FileMaxChunkSize)
    {
        qWarning() << "rejecting chunk because size mismatch";
        return;
    }
    else
    {
        auto& itr = it->second;
        const auto& chunk_data = message.chunk_data();
        itr.stream.write(chunk_data.data(), chunk_data.size());

        // emit progress callback
        const auto fileId = message.file_id();
        const auto written = itr.stream.tellg();
        const auto total = itr.size;

        emit this->fileTransferProgress(fileId, tego_attachment_direction_receiving, written, total);

        auto response = std::make_unique<Data::File::FileChunkAck>();
        response->set_file_id(message.file_id());
        response->set_bytes_received(written);

        Data::File::Packet packet;
        packet.set_allocated_file_chunk_ack(response.release());
        Channel::sendMessage(packet);

        if (written == total)
        {
            /* sha3_512 validation */

            // reset the read/write stream and calculate the file hash
            itr.stream.seekg(0);
            tego_file_hash fileHash(itr.stream);
            itr.stream.close();

            if (fileHash.to_string() != itr.sha3_512)
            {
                // delete file if calculated hash doesn't match expected
                QFile::remove(QString::fromStdString(itr.partial_dest()));
                emit this->fileTransferFinished(fileId, tego_attachment_direction_receiving, tego_attachment_result_bad_hash);
            }
            else
            {
                // if a file already exists at our final destination, then remove it
                const auto qDest = QString::fromStdString(itr.dest);
                if (QFile::exists(qDest))
                {
                    QFile::remove(qDest);
                }

                const auto qPartialDest = QString::fromStdString(itr.partial_dest());
                if(QFile::rename(qPartialDest, qDest))
                {
                    emit this->fileTransferFinished(fileId, tego_attachment_direction_receiving, tego_attachment_result_success);
                    logTransferStats(itr.size, itr.beginTime);
                }
                else
                {
                    emit this->fileTransferFinished(fileId, tego_attachment_direction_receiving, tego_attachment_result_failure);
                }
            }
            incomingTransfers.erase(it);

            // send complete notification to remote user
            auto notification = std::make_unique<Data::File::FileTransferCompleteNotification>();
            notification->set_file_id(fileId);
            notification->set_result(Protocol::Data::File::Success);

            Data::File::Packet packet;
            packet.set_allocated_file_transfer_complete_notification(notification.release());
            Channel::sendMessage(packet);
        }
    }


}

void FileChannel::handleFileChunkAck(const Data::File::FileChunkAck &message)
{
    const auto id = message.file_id();

    auto it = outgoingTransfers.find(id);
    if (it == outgoingTransfers.end())
    {
        qWarning() << "recieved ack for a chunk we never sent";
        return;
    }

    const auto& otr = it->second;
    emit this->fileTransferProgress(otr.id, tego_attachment_direction_receiving, message.bytes_received(), otr.size);
}

// verify that our tego_attachment_result_t enum matches the FileTransferResult enum
namespace
{
    typedef std::underlying_type_t<Protocol::Data::File::FileTransferResult> underlying_t;

    static_assert(std::is_same_v<std::underlying_type_t<Protocol::Data::File::FileTransferResult>, std::underlying_type_t<tego_attachment_result_t>>);
    static_assert(static_cast<underlying_t>(Protocol::Data::File::Success) == static_cast<underlying_t>(tego_attachment_result_success));
    static_assert(static_cast<underlying_t>(Protocol::Data::File::Cancelled) == static_cast<underlying_t>(tego_attachment_result_cancelled));
    static_assert(static_cast<underlying_t>(Protocol::Data::File::Failure) == static_cast<underlying_t>(tego_attachment_result_failure));

}

void FileChannel::handleFileTransferCompleteNotification(const Data::File::FileTransferCompleteNotification &message)
{
    const auto id = message.file_id();

    // first look for an outgoing transfer with this id and cancel, erase it
    if (auto it = outgoingTransfers.find(id); it != outgoingTransfers.end())
    {
        const auto& otr = it->second;
        if (message.result() == tego_attachment_result_success)
        {
            logTransferStats(otr.size, otr.beginTime);
        }

        outgoingTransfers.erase(it);
        emit fileTransferFinished(id, tego_attachment_direction_sending, static_cast<tego_attachment_result_t>(message.result()));
    }
    else if( auto it = incomingTransfers.find(id); it != incomingTransfers.end())
    {
        incomingTransfers.erase(it);
        emit fileTransferFinished(id, tego_attachment_direction_receiving, static_cast<tego_attachment_result_t>(message.result()));
    }
    else
    {
        qWarning() << "received cancel request for unknown transfer:" << id;
    }
}

bool FileChannel::sendFileWithId(QString file_uri,
                                 QString file_hash,
                                 QDateTime,
                                 file_id_t file_id)
{
    if (direction() != Outbound) {
        BUG() << "Attempted to send outbound message on non outbound channel";
        return false;
    }

    if (file_uri.isEmpty()) {
        BUG() << "File URI is empty, this should never have been reached";
        return false;
    }

    /* only allow regular files or symlinks chains to regular files */
    QFileInfo fi(file_uri);
    auto file_path = fi.canonicalFilePath().toStdString();
    if (file_path.size() == 0) {
        qWarning() << "Could net resolve file path";
        return false;
    }

    const auto file_size = fi.size();

    // create our record
    outgoing_transfer_record qf(file_id, file_path, file_size);
    if (!qf.stream.is_open())
    {
        qWarning() << "Failed to open file for sending header";
        return false;
    }
    outgoingTransfers.insert({file_id, std::move(qf)});

    auto header = std::make_unique<Data::File::FileHeader>();
    header->set_file_id(file_id);
    header->set_size(file_size);
    header->set_sha3_512(file_hash.toStdString());
    header->set_name(fi.fileName().toStdString());

    Data::File::Packet packet;
    packet.set_allocated_file_header(header.release());

    Channel::sendMessage(packet);

    /* the first chunk will get sent after the first header ack */
    return true;
}

void FileChannel::acceptFile(tego_attachment_id_t fileId, const std::string& dest)
{
    auto it = incomingTransfers.find(fileId);
    TEGO_THROW_IF_FALSE(it != incomingTransfers.end());
    auto& itr = it->second;

    itr.beginTime = std::chrono::system_clock::now();
    itr.open_stream(dest);

    auto response = std::make_unique<Data::File::FileHeaderResponse>();
    response->set_response(tego_attachment_response_accept);
    response->set_file_id(fileId);

    Data::File::Packet packet;
    packet.set_allocated_file_header_response(response.release());
    Channel::sendMessage(packet);

    // emit starting transfer progress callback
    emit this->fileTransferProgress(fileId, tego_attachment_direction_receiving, 0, it->second.size);
}

void FileChannel::rejectFile(tego_attachment_id_t fileId)
{
    auto it = incomingTransfers.find(fileId);
    TEGO_THROW_IF_FALSE(it != incomingTransfers.end());

    // remove the incoming_transfer_record from our list on reject
    incomingTransfers.erase(it);

    auto response = std::make_unique<Data::File::FileHeaderResponse>();
    response->set_response(tego_attachment_response_reject);
    response->set_file_id(fileId);

    Data::File::Packet packet;
    packet.set_allocated_file_header_response(response.release());
    Channel::sendMessage(packet);

    emit fileTransferFinished(fileId, tego_attachment_direction_receiving, tego_attachment_result_rejected);
}

bool FileChannel::cancelTransfer(tego_attachment_id_t fileId)
{
    // verify the transfer exists in our system
    if (auto it = incomingTransfers.find(fileId); it != incomingTransfers.end())
    {
        incomingTransfers.erase(it);

    }
    else if (auto it = outgoingTransfers.find(fileId); it != outgoingTransfers.end())
    {
        outgoingTransfers.erase(it);
    }
    else
    {
        return false;
    }

    // finally send cancel notification to remote user
    auto notification = std::make_unique<Data::File::FileTransferCompleteNotification>();
    notification->set_file_id(fileId);
    notification->set_result(Protocol::Data::File::Cancelled);

    Data::File::Packet packet;
    packet.set_allocated_file_transfer_complete_notification(notification.release());
    Channel::sendMessage(packet);

    emit fileTransferFinished(fileId, tego_attachment_direction_receiving, tego_attachment_result_cancelled);

    return true;
}

void FileChannel::sendNextChunk(file_id_t id)
{
    if (direction() != Outbound) {
        BUG() << "Attempted to send outbound message on non outbound channel";
        return;
    }

    auto it = outgoingTransfers.find(id);
    if (it == outgoingTransfers.end())
    {
        BUG() << "Attemping to send next chunk for unknown file" << id;
        return;
    }
    auto& otr = it->second;

    // make sure our offset and the stream offset agree
    Q_ASSERT(otr.finished() == false);
    Q_ASSERT(otr.offset == otr.stream.tellg());

    // read the next chunk to our buffer, and update our offset
    otr.stream.read(this->chunkBuffer, FileMaxChunkSize);
    const auto chunkSize = otr.stream.gcount();
    otr.offset += chunkSize;

    // build our chunk
    auto chunk = std::make_unique<Data::File::FileChunk>();
    chunk->set_file_id(id);
    chunk->set_chunk_data(std::begin(chunkBuffer), chunkSize);

    Data::File::Packet packet;
    packet.set_allocated_file_chunk(chunk.release());

    // send the chunk
    Channel::sendMessage(packet);

    // schedule sending next chunk
    if (otr.offset < otr.size)
    {
        QTimer::singleShot(0, [=,this]() -> void {this->sendNextChunk(id);});
    }
}

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

FileChannel::FileChannel(Direction direction, Connection *connection)
    : Channel(QStringLiteral("im.ricochet.file-transfer"), direction, connection)
{
}

size_t FileChannel::fsize_to_chunks(size_t sz)
{
    return (sz + (FileMaxChunkSize - 1)) / FileMaxChunkSize;
}

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
    } else if (message.has_file_chunk()) {
        handleFileChunk(message.file_chunk());
    } else if (message.has_file_chunk_ack()) {
        handleFileChunkAck(message.file_chunk_ack());
    } else if (message.has_file_header_ack()) {
        handleFileHeaderAck(message.file_header_ack());
    } else {
        qWarning() << "Unrecognized file packet on " << type();
        closeChannel();
    }
}

void FileChannel::handleFileHeader(const Data::File::FileHeader &message)
{
    Data::File::FileHeaderAck *response = new Data::File::FileHeaderAck; //todo: replace this with a unique_ptr

    if (direction() != Inbound) {
        qWarning() << "Rejected inbound message (FileHeader) on an outbound channel";
        response->set_accepted(false);
    } else if (!message.has_size() || !message.has_chunk_count()) {
        /* rationale:
         *  - if there's no size, we know when we've reached the end when cur_chunk == n_chunks
         *  - if there's no chunk count, we know when we've reached the end when total_bytes >= size
         *  - if there's neither, size cannot be determined */
        /* TODO: given ^, are both actually needed? */
        qWarning() << "Rejected file header with missing size";
        response->set_accepted(false);
    } else if (!message.has_sha3_512()) {
        qWarning() << "Rejected file header with missing hash (sha3_512) - cannot validate";
        response->set_accepted(false);
    } else if (!message.has_file_id()) {
        qWarning() << "Rejected file header with missing id";
        response->set_accepted(false);
    } else if (!message.has_chunk_count()) {
        qWarning() << "Rejected file header with missing chunk count";
        response->set_accepted(false);
    } else if (!message.has_name()) {
        qWarning() << "Rejected file header with missing name";
        response->set_accepted(false);
    } else if (message.name().find("..") != std::string::npos) {
        qWarning() << "Rejected file header with name containing '..'";
    } else if (message.name().find("/") != std::string::npos) {
        qWarning() << "Rejected file header with name containing '/'";
    } else {
        response->set_accepted(true);
        /* Use the file id and onion url as part of the directory name */
        QString dirname = QString::fromStdString(fmt::format("{}/ricochet-{}-{}",
                                                    QStandardPaths::writableLocation(QStandardPaths::TempLocation),
                                                    connection()->serverHostname().remove(".onion").toStdString(),
                                                    message.file_id()));

        /* create directory to store chunks in /tmp */
        logger::println("Creating temp directory: {}", dirname);
        QDir dir;
        if (!dir.mkdir(dirname)) {
            qWarning() << "Could not create tmp directory" << dirname ;
            response->set_accepted(false);
        }

        if (response->accepted())
        {
            const auto id = message.file_id();
            incoming_transfer_record ifr =
            {
                message.size(),
                0,
                message.chunk_count(),
                message.chunk_count(),
                dirname.toStdString(),
                message.sha3_512(),
                message.has_name() ? message.name() : std::to_string(message.file_id()),
            };

            // TODO: change the protocol to send a byte buffer of the exact size?
            TEGO_THROW_IF_FALSE_MSG(ifr.sha3_512.size() == (tego_file_hash::STRING_SIZE - 1));
            tego_file_hash fileHash;
            fileHash.hex = ifr.sha3_512;

            emit this->fileRequestReceived(id, QString::fromStdString(ifr.name), ifr.size, std::move(fileHash));

            // if rejected the prf should be removed from this list
            incomingTransfers.insert({id, std::move(ifr)});
        }
    }
}

void FileChannel::handleFileChunk(const Data::File::FileChunk &message)
{
    auto response = std::make_unique<Data::File::FileChunkAck>();
    response->set_file_chunk_id(message.chunk_id());
    response->set_file_id(message.file_id());
    response->set_accepted(false);

    auto it = incomingTransfers.find(message.file_id());
    if (it == incomingTransfers.end()) {
        qWarning() << "rejecting chunk for unknown file";
        response->set_accepted(false);
    }
    else if (message.chunk_size() > FileMaxChunkSize ||
        message.chunk_size() != message.chunk_data().length())
    {
        qWarning() << "rejecting chunk because size mismatch";
        response->set_accepted(false);
    }
    else
    {
        auto& itr = it->second;
        response->set_accepted(true);

        tego_file_hash chunkHash(
            reinterpret_cast<uint8_t const*>(message.chunk_data().c_str()),
            reinterpret_cast<uint8_t const*>(message.chunk_data().c_str()) + message.chunk_size());

        logger::println("Receiving file:chunk {}:{} with hash: {}", message.file_id(), message.chunk_id(), chunkHash.to_string());

        if (chunkHash.to_string() != message.sha3_512())
        {
            response->set_accepted(false);
        }
        else
        {
            std::string chunk_path = itr.path + std::to_string(message.chunk_id());
            std::fstream chunk_file(chunk_path, std::ios::out | std::ios::binary | std::ios::trunc);

            if (!chunk_file.is_open()) {
                BUG() << "could not open temp file for chunk (are permissions set correctly?)";
            }

            chunk_file.write(message.chunk_data().c_str(), message.chunk_size());
            chunk_file.close();
            itr.missing_chunks--;

            // emit progress callback
            const auto fileId = message.file_id();
            const auto written = message.chunk_id() * FileMaxChunkSize + message.chunk_size();
            const auto total = itr.size;

            emit this->fileTransferProgress(fileId, tego_attachment_direction_receiving, written, total);

            if (itr.missing_chunks == 0)
            {
                /* successfully finished transfer */

                /* concatenate chunks into one file */
                std::string outf_path = itr.path + "out";
                std::ofstream out_file(outf_path, std::ios::out | std::ios::binary | std::ios::trunc);
                if (!out_file.is_open()) {
                    BUG() << "could not open temp file for out file (are permissions set correctly?)";
                }

                for (chunk_id_t i = 0; i < itr.n_chunks; i++) {
                    std::string chunk_path = itr.path + std::to_string(i);
                    std::fstream chunk_file(chunk_path, std::ios::in);

                    if (!chunk_file.is_open()) {
                        BUG() << "could not open chunk file for reading";
                    }

                    out_file << chunk_file.rdbuf();
                    chunk_file.close();

                    QDir dir;
                    dir.remove(QString::fromStdString(chunk_path));
                }

                out_file.close();

                /* sha3_512 validation */
                std::ifstream fileStream(outf_path, std::ios::in | std::ios::binary);
                TEGO_THROW_IF_FALSE_MSG(fileStream.is_open(), "Could not open file for reading: {}", outf_path);

                // delete file if calculated hash doesn't match expected
                if (tego_file_hash fileHash(fileStream);
                    fileHash.to_string() != itr.sha3_512)
                {
                    //todo: handle this better, error should probably surface to user yeah?
                    QDir dir;
                    dir.remove(QString::fromStdString(outf_path));
                    closeChannel();
                    TEGO_THROW_MSG("Hash of completed file {} is {}, was expecting {}", outf_path, fileHash.to_string(),itr.sha3_512);
                    return;
                }
                //todo: signals

                /* move the file to downloads */
                std::string new_out_path = fmt::format("{}/{}", QStandardPaths::writableLocation(QStandardPaths::DownloadLocation), itr.name);
                QFile::rename(QString::fromStdString(outf_path), QString::fromStdString(new_out_path));

                incomingTransfers.erase(it);
                // todo: erase tmp dir (or better yet, put the temp dir in the same place as our destination path)
            }
        }
    }

    Data::File::Packet packet;
    packet.set_allocated_file_chunk_ack(response.release());
    Channel::sendMessage(packet);
}

void FileChannel::handleFileChunkAck(const Data::File::FileChunkAck &message)
{
    const auto id = message.file_id();

    auto it = outgoingTransfers.find(id);
    if (it == outgoingTransfers.end() ||
        it->second.cur_chunk != message.file_chunk_id())
    {
        qWarning() << "recieved ack for a chunk we never sent";
        return;
    }
    auto& otr = it->second;

    // increment chunk index for sendChunkWithId
    if(message.accepted())
    {
        otr.cur_chunk++;
    }

    const auto offset = otr.cur_chunk * FileMaxChunkSize;

    // check if this is our last chunk
    if (offset >= otr.size) {
        otr.finished = true;
        outgoingTransfers.erase(it);
        return;
    }

    sendChunkWithId(id, otr.path, otr.cur_chunk);
}

void FileChannel::handleFileHeaderAck(const Data::File::FileHeaderAck &message)
{
    if (direction() != Outbound) {
        qWarning() << "Rejected inbound message on inbound file channel";
        return;
    }

    const auto id = message.file_id();

    auto it = outgoingTransfers.find(id);
    if (it == outgoingTransfers.end())
    {
        qWarning() << "recieved ack for a file header we never sent";
        return;
    }

    /* start the transfer at chunk 0 */
    if (message.accepted())
    {
        //todo: message_acknowledged signal/callback needs to go here, before the call to sendChunkWithId
        auto& otr = it->second;
        sendChunkWithId(id, otr.path, 0);
    }
    else
    {
        // receiver rejectd our transfer request, so erase it from our records
        outgoingTransfers.erase(it);
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

    /* sendNextChunk will resume a transfer if connection was interrupted */
    if (sendNextChunk(file_id)) return true;

    /* only allow regular files or symlinks chains to regular files */
    QFileInfo fi(file_uri);
    QString file_path = fi.canonicalFilePath();
    if (file_path.size() == 0) {
        qWarning() << "Could net resolve file path";
        return false;
    }

    auto file_size = fi.size();

    auto file_chunks = fsize_to_chunks(file_size);
    std::ifstream file(file_path.toStdString(), std::ios::in | std::ios::binary);
    if (!file) {
        qWarning() << "Failed to open file for sending header";
        return false;
    }
    file.close();

    outgoing_transfer_record qf =
    {
        file_path.toStdString(),
        file_size,
        0,
        false,
        false,
    };

    outgoingTransfers.insert({file_id, std::move(qf)});

    Data::File::FileHeader *header = new Data::File::FileHeader; //todo: replace this with a unique_ptr
    header->set_file_id(file_id);
    header->set_size(file_size);
    header->set_chunk_count(file_chunks);
    header->set_sha3_512(file_hash.toStdString());
    header->set_name(fi.fileName().toStdString());

    Data::File::Packet packet;
    packet.set_allocated_file_header(header);

    Channel::sendMessage(packet);

    /* the first chunk will get sent after the first header ack */
    return true;
}

void FileChannel::acceptFile(tego_attachment_id_t fileId, const std::string& dest)
{
    auto it = incomingTransfers.find(fileId);
    TEGO_THROW_IF_FALSE(it != incomingTransfers.end());
    auto& itr = it->second;

    // attempt to open the destinatin for writing
    std::fstream destFile(dest, std::ios::out | std::ios::binary);
    TEGO_THROW_IF_FALSE(destFile.is_open());
    destFile.close();

    // todo: we need to rework the path and name logic of incoming_transfer_record
    itr.name = dest;

    auto response = std::make_unique<Data::File::FileHeaderAck>();
    response->set_accepted(true);
    response->set_file_id(fileId);

    Data::File::Packet packet;
    packet.set_allocated_file_header_ack(response.release());
    Channel::sendMessage(packet);
}

void FileChannel::rejectFile(tego_attachment_id_t fileId)
{
    auto it = incomingTransfers.find(fileId);
    TEGO_THROW_IF_FALSE(it != incomingTransfers.end());

    // remove the incoming_transfer_record from our list on reject
    incomingTransfers.erase(it);

    auto response = std::make_unique<Data::File::FileHeaderAck>();
    response->set_accepted(false);
    response->set_file_id(fileId);

    Data::File::Packet packet;
    packet.set_allocated_file_header_ack(response.release());
    Channel::sendMessage(packet);
}

void FileChannel::cancelTransfer(tego_attachment_id_t fileId)
{

}

bool FileChannel::sendNextChunk(file_id_t id) {
    //TODO: check either file digest or file last modified time, if they don't match before, start from chunk 0
    auto it = outgoingTransfers.find(id);

    if (it == outgoingTransfers.end())
    {
        return false;
    }

    auto& otr = it->second;
    if (otr.cur_chunk * FileMaxChunkSize > otr.size)
    {
        otr.finished = true;
    }
    if (otr.finished)
    {
        // xxx: we should never be here, this function should not ever be called if the transfer is finished
        return false;
    }

    return sendChunkWithId(id, otr.path, otr.cur_chunk++);
}

bool FileChannel::sendChunkWithId(file_id_t fid, std::string &fpath, chunk_id_t cid)
{
    if (direction() != Outbound) {
        BUG() << "Attempted to send outbound message on non outbound channel";
        return false;
    }

    std::ifstream file(fpath, std::ios::in | std::ios::binary);
    if (!file)
    {
        qWarning() << "Failed to open file for sending chunk";
        return false;
    }

    QFileInfo fi(QString::fromStdString(fpath));
    const qint64 file_size = fi.size();
    const qint64 offset = cid * FileMaxChunkSize;

    TEGO_THROW_IF_FALSE(file_size >= 0 && offset >= 0);

    if (offset >= file_size)
    {
        qWarning() << "Attempted to start read beyond eof";
        return false;
    }

    /* go to the pos of the chunk */
    file.seekg(offset);
    if (!file)
    {
        qWarning() << "Failed to seek to last position in file for chunking";
        return false;
    }

    auto buf = std::make_unique<char[]>(FileMaxChunkSize);

    file.read(buf.get(), FileMaxChunkSize);
    auto bytes_read = file.gcount();
    /* the only time bytes_read would be >FileMaxChunkSize is if gcount thinks the
     * amount of bytes read is unrepresentable, in which case something has
     * gone wrong */
    TEGO_THROW_IF_TRUE_MSG(bytes_read > FileMaxChunkSize, "Invalid amount of bytes read");

    tego_file_hash chunkHash(
        reinterpret_cast<uint8_t const*>(buf.get()),
        reinterpret_cast<uint8_t const*>(buf.get()) + bytes_read);

    logger::println("Sending file:chunk {}:{} with hash: {}", fid, cid, chunkHash.to_string());

    /* send this chunk */
    auto chunk = std::make_unique<Data::File::FileChunk>();
    chunk->set_sha3_512(chunkHash.to_string());
    chunk->set_file_id(fid);
    chunk->set_chunk_id(cid);
    chunk->set_chunk_size(bytes_read);
    chunk->set_chunk_data(buf.get(), bytes_read);
    //TODO chunk.set_time_delta();
    Data::File::Packet packet;
    packet.set_allocated_file_chunk(chunk.release());
    file.close();

    Channel::sendMessage(packet);
    emit this->fileTransferProgress(fid, tego_attachment_direction_sending, offset + bytes_read, file_size);
    return true;
}

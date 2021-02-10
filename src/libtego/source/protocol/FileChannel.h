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

#ifndef PROTOCOL_FILECHANNEL_H
#define PROTOCOL_FILECHANNEL_H

#include "protocol/Channel.h"
#include "protocol/FileChannel.pb.h"
#include "tego/tego.h"
#include "file_hash.hpp"

namespace Protocol
{

class FileChannel : public Channel
{
    Q_OBJECT;
    Q_DISABLE_COPY(FileChannel);

public:
    typedef quint32 file_id_t;
    typedef quint32 chunk_id_t;
    // 63 kb, max packet size is UINT16_MAX (ak 65535, 64k - 1) so leave space for other data
    constexpr static qint64 FileMaxChunkSize = 63*1024;

    explicit FileChannel(Direction direction, Connection *connection);

    bool sendFileWithId(QString file_url, QString file_hash, QDateTime time, file_id_t id);
    void acceptFile(tego_attachment_id_t fileId, const std::string& dest);
    void rejectFile(tego_attachment_id_t fileId);
    void cancelTransfer(tego_attachment_id_t fileId);

signals:
    void fileRequestReceived(file_id_t id, QString fileName, size_t fileSize, tego_file_hash_t);
    void fileReceived(const QDateTime &time, file_id_t id);
    void fileAcknowledged(file_id_t id, tego_bool_t accepted);
    void fileTransferProgress(file_id_t id, tego_attachment_direction_t direction, uint64_t bytesTransmitted, uint64_t bytesTotal);

protected:
    virtual bool allowInboundChannelRequest(const Data::Control::OpenChannel *request, Data::Control::ChannelResult *result);
    virtual bool allowOutboundChannelRequest(Data::Control::OpenChannel *request);
    virtual void receivePacket(const QByteArray &packet);
private:
    size_t fsize_to_chunks(size_t sz);

    struct outgoing_transfer_record
    {
        std::string path;
        const qint64 size = 0;
        chunk_id_t cur_chunk = 0;
        bool finished = false;
        bool peer_did_accept = false;
    };

    struct incoming_transfer_record
	{
        const size_t size = 0;
        chunk_id_t cur_chunk = 0;
        const chunk_id_t n_chunks = 0;
        chunk_id_t missing_chunks = 0;
        const std::string path;
        const std::string sha3_512;
        std::string name;
    };

    // file transfers we are sending
    std::map<file_id_t, outgoing_transfer_record> outgoingTransfers;
    // file transfers we are receiving
    std::map<file_id_t, incoming_transfer_record> incomingTransfers;

    void handleFileHeader(const Data::File::FileHeader &message);
    void handleFileChunk(const Data::File::FileChunk &message);
    void handleFileChunkAck(const Data::File::FileChunkAck &message);
    void handleFileHeaderAck(const Data::File::FileHeaderAck &message);
    bool sendChunkWithId(file_id_t fid, std::string &fpath, chunk_id_t cid);
    bool sendNextChunk(file_id_t id);
};

}

#endif
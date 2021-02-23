#include "ContactUser.h"
#include "ConversationModel.h"
#include "UserIdentity.h"

namespace shims
{
    ConversationModel::ConversationModel(QObject *parent)
    : QAbstractListModel(parent)
    , contactUser(nullptr)
    , messages({})
    , unreadCount(0)
    {
        connect(this, &ConversationModel::unreadCountChanged, [self=this](int prevCount, int currentCount) -> void
        {
            static int globalUnreadCount = 0;

            const auto delta = currentCount - prevCount;
            globalUnreadCount += delta;

            qDebug() << "globalUnreadCount:" << globalUnreadCount;
#ifdef Q_OS_MAC
            QtMac::setBadgeLabelText(globalUnreadCount == 0 ? QString() : QString::number(globalUnreadCount));
#endif
        });
    }

    QHash<int,QByteArray> ConversationModel::roleNames() const
    {
        QHash<int, QByteArray> roles;
        roles[Qt::DisplayRole] = "text";
        roles[TimestampRole] = "timestamp";
        roles[IsOutgoingRole] = "isOutgoing";
        roles[StatusRole] = "status";
        roles[SectionRole] = "section";
        roles[TimespanRole] = "timespan";
        roles[TypeRole] = "type";
        roles[TransferRole] = "transfer";
        return roles;
    }

    int ConversationModel::rowCount(const QModelIndex &parent) const
    {
        if (parent.isValid())
            return 0;
        return messages.size();
    }

    QVariant ConversationModel::data(const QModelIndex &index, int role) const
    {
        if (!index.isValid() || index.row() >= messages.size())
            return QVariant();

        const MessageData &message = messages[index.row()];

        switch (role) {
            case Qt::DisplayRole:
                if (message.type == TextMessage)
                {
                    return message.text;
                }
                else
                {
                    return QStringLiteral("not a text message");
                }

            case TimestampRole: return message.time;
            case IsOutgoingRole: return message.status != Received;
            case StatusRole: return message.status;

            case SectionRole: {
                if (contact()->getStatus() == ContactUser::Online)
                    return QString();
                if (index.row() < messages.size() - 1) {
                    const MessageData &next = messages[index.row()+1];
                    if (next.status != Received && next.status != Delivered)
                        return QString();
                }
                for (int i = 0; i <= index.row(); i++) {
                    if (messages[i].status == Received || messages[i].status == Delivered)
                        return QString();
                }
                return QStringLiteral("offline");
            }
            case TimespanRole: {
                if (index.row() < messages.size() - 1)
                    return messages[index.row() + 1].time.secsTo(messages[index.row()].time);
                else
                    return -1;
            }
            case TypeRole: {
                if (message.type == TextMessage) {
                    return QStringLiteral("text");
                }
                else if (message.type == TransferMessage) {
                    return QStringLiteral("transfer");
                }
                else {
                    return QStringLiteral("invalid");
                }
            case TransferRole:
                if (message.type == TransferMessage)
                {
                    QVariantMap transfer;
                    transfer["file_name"] = message.fileName;
                    transfer["file_size"] = message.fileSize;
                    transfer["file_hash"] = message.fileHash;
                    transfer["id"] = message.identifier;
                    transfer["status"] = message.transferStatus;
                    transfer["statusString"] = [=]()
                    {
                        switch(message.transferStatus)
                        {
                            case Pending: return tr("Pending");
                            case InProgress:
                            {
                                const auto locale = QLocale::system();
                                return QString("%1 / %2").arg(locale.formattedDataSize(message.bytesTransferred)).arg(locale.formattedDataSize(message.fileSize));
                            }
                            case Cancelled: return tr("Cancelled");
                            case Finished: return tr("Complete");
                            case Rejected: return tr("Rejected");
                            default: return tr("Invalid");
                        }
                    }();
                    transfer["progressPercent"] = double(message.bytesTransferred) / double(message.fileSize);
                    transfer["direction"] = message.transferDirection == tego_attachment_direction_sending ? QStringLiteral("sending") : QStringLiteral("receiving");

                    return transfer;
                }
            }
        }

        return QVariant();
    }

    shims::ContactUser* ConversationModel::contact() const
    {
        return contactUser;
    }

    void ConversationModel::setContact(shims::ContactUser *contact)
    {
        this->contactUser = contact;
        emit contactChanged();
    }

    int ConversationModel::getUnreadCount() const
    {
        return unreadCount;
    }

    void ConversationModel::resetUnreadCount()
    {
        this->setUnreadCount(0);
    }

    void ConversationModel::setUnreadCount(int count)
    {
        Q_ASSERT(count >= 0);

        const auto oldUnreadCount = this->unreadCount;
        if(oldUnreadCount != count)
        {
            this->unreadCount = count;
            emit unreadCountChanged(oldUnreadCount, unreadCount);

            auto userIdentity = shims::UserIdentity::userIdentity;
            auto contactsManager = userIdentity->getContacts();
            contactsManager->setUnreadCount(this->contactUser, count);
        }
    }

    void ConversationModel::sendMessage(const QString &text)
    {
        logger::println("sendMessage : {}", text);
        auto userIdentity = shims::UserIdentity::userIdentity;
        auto context = userIdentity->getContext();

        auto utf8Str = text.toUtf8();
        if (utf8Str.size() == 0)
        {
            return;
        }

        const auto userId = this->contactUser->toTegoUserId();
        tego_message_id_t messageId = 0;

        // send message and save off the id associated with it
        tego_context_send_message(
            context,
            userId.get(),
            utf8Str.data(),
            utf8Str.size(),
            &messageId,
            tego::throw_on_error());

        // store data locally for UI
        MessageData md;
        md.type = TextMessage;
        md.text = text;
        md.time = QDateTime::currentDateTime();
        md.identifier = messageId;
        md.status = Queued;

        this->beginInsertRows(QModelIndex(), 0, 0);
        this->messages.prepend(std::move(md));
        this->endInsertRows();
    }

    void ConversationModel::sendFile()
    {
        auto filePath =
            QFileDialog::getOpenFileName(
                nullptr,
                tr("Open File"),
                QDir::homePath(),
                nullptr);

        if (!filePath.isEmpty())
        {
            auto userIdentity = shims::UserIdentity::userIdentity;
            auto context = userIdentity->getContext();
            const auto path = filePath.toUtf8();
            const auto userId = this->contactUser->toTegoUserId();
            tego_attachment_id_t attachmentId;
            std::unique_ptr<tego_file_hash_t> fileHash;
            tego_file_size_t fileSize = 0;

            try
            {

                tego_context_send_attachment_request(
                    context,
                    userId.get(),
                    path.data(),
                    path.size(),
                    &attachmentId,
                    tego::out(fileHash),
                    &fileSize,
                    tego::throw_on_error());

                logger::println("send file request id : {}, hash : {}", attachmentId, tego::to_string(fileHash.get()));

                MessageData md;
                md.type = TransferMessage;
                md.identifier = attachmentId;
                md.time = QDateTime::currentDateTime();
                md.status = Queued;

                md.fileName = QFileInfo(filePath).fileName();
                md.fileSize = fileSize;
                md.fileHash = QString::fromStdString(tego::to_string(fileHash.get()));
                md.transferStatus = Pending;

                this->beginInsertRows(QModelIndex(), 0, 0);
                this->messages.prepend(std::move(md));
                this->endInsertRows();
            }
            catch(const std::runtime_error& err)
            {
                qWarning() << err.what();
            }
        }
    }

    void ConversationModel::attachmentRequestReceived(tego_attachment_id_t attachmentId, QString fileName, QString fileHash, quint64 fileSize)
    {
        logger::println("attachmentRequestReceived: {}, {}, {}, {}", attachmentId, fileName, fileHash, fileSize);

        MessageData md;
        md.type = TransferMessage;
        md.identifier = attachmentId;
        md.time = QDateTime::currentDateTime();
        md.status = Received;

        md.fileName = std::move(fileName);
        md.fileHash = std::move(fileHash);
        md.fileSize = fileSize;
        md.transferStatus = Pending;

        this->beginInsertRows(QModelIndex(), 0, 0);
        this->messages.prepend(std::move(md));
        this->endInsertRows();

        this->setUnreadCount(this->unreadCount + 1);
    }

    void ConversationModel::attachmentRequestAcknowledged(tego_attachment_id_t attachmentId, bool accepted)
    {
        auto row = this->indexOfOutgoingMessage(attachmentId);
        Q_ASSERT(row >= 0);

        MessageData &data = messages[row];
        data.status = accepted ? Delivered : Error;
        emitDataChanged(row);
    }

    void ConversationModel::attachmentRequestResponded(tego_attachment_id_t attachmentId, tego_attachment_response_t response)
    {
        auto row = this->indexOfOutgoingMessage(attachmentId);
        Q_ASSERT(row >= 0);

        MessageData &data = messages[row];
        switch(response)
        {
            case tego_attachment_response_accept:
                data.transferStatus = Pending;
                break;
            case tego_attachment_response_reject:
                data.transferStatus = Rejected;
                break;
            default:
                return;
        }

        emitDataChanged(row);
    }

    void ConversationModel::cancelAttachmentTransfer(tego_attachment_id_t attachmentId)
    {
        // we get the cancelled callback if we cancel or if the other user cancelled,
        // so ensure we only do work if it was the other preson cancelling
        auto row = this->indexOfMessage(attachmentId);
        if (row < 0)
        {
            return;
        }

        MessageData &data = messages[row];
        if (data.transferStatus != Cancelled)
        {
            data.transferStatus = Cancelled;
            emitDataChanged(row);

            logger::println("request to cancel attachment transfer: {}", attachmentId);

            auto userIdentity = shims::UserIdentity::userIdentity;
            auto context = userIdentity->getContext();
            const auto userId = this->contactUser->toTegoUserId();

            try
            {
                tego_context_cancel_attachment_transfer(
                    context,
                    userId.get(),
                    attachmentId,
                    tego::throw_on_error());
            }
            catch(const std::runtime_error& err)
            {
                qWarning() << err.what();
            }
        }
    }

    void ConversationModel::attachmentRequestProgressUpdated(tego_attachment_id_t attachmentId, quint64 bytesTransferred)
    {
        auto row = this->indexOfMessage(attachmentId);
        if (row >= 0)
        {
            MessageData &data = messages[row];
            data.bytesTransferred = bytesTransferred;
            data.transferStatus = InProgress;

            emitDataChanged(row);
        }
    }

    void ConversationModel::attachmentRequestTransferCompleted(tego_attachment_id_t attachmentId)
    {
        auto row = this->indexOfMessage(attachmentId);
        if (row >= 0)
        {
            MessageData &data = messages[row];
            data.transferStatus = Finished;

            emitDataChanged(row);
        }
    }

    void ConversationModel::clear()
    {
        if (messages.isEmpty())
        {
            return;
        }

        beginRemoveRows(QModelIndex(), 0, messages.size()-1);
        messages.clear();
        endRemoveRows();

        resetUnreadCount();
    }

    void ConversationModel::messageReceived(tego_message_id_t messageId, QDateTime timestamp, const QString& text)
    {
        logger::trace();
        logger::println(" messageId : {}", messageId);
        logger::println(" text : '{}'", text);
        logger::println(" time : {}", timestamp.toString());

        MessageData md;
        md.type = TextMessage;
        md.text = text;
        md.time = timestamp;
        md.identifier = messageId;
        md.status = Received;

        this->beginInsertRows(QModelIndex(), 0, 0);
        this->messages.prepend(std::move(md));
        this->endInsertRows();

        this->setUnreadCount(this->unreadCount + 1);
    }

    void ConversationModel::messageAcknowledged(tego_message_id_t messageId, bool accepted)
    {
        auto row = this->indexOfOutgoingMessage(messageId);
        Q_ASSERT(row >= 0);

        MessageData &data = messages[row];
        data.status = accepted ? Delivered : Error;
        emitDataChanged(row);
    }

    void ConversationModel::emitDataChanged(int row)
    {
        Q_ASSERT(row >= 0);
        emit dataChanged(index(row, 0), index(row, 0));
    }

    int ConversationModel::indexOfMessage(quint32 identifier) const
    {
        for (int i = 0; i < messages.size(); i++) {
            const auto& currentMessage = messages[i];

            if (currentMessage.identifier == identifier)
                return i;
        }
        return -1;
    }

    int ConversationModel::indexOfOutgoingMessage(quint32 identifier) const
    {
        for (int i = 0; i < messages.size(); i++) {
            const auto& currentMessage = messages[i];

            if (currentMessage.identifier == identifier && (currentMessage.status != Received))
                return i;
        }
        return -1;
    }

    int ConversationModel::indexOfIncomingMessage(quint32 identifier) const
    {
        for (int i = 0; i < messages.size(); i++) {
            const auto& currentMessage = messages[i];

            if (currentMessage.identifier == identifier && (currentMessage.status == Received))
                return i;
        }
        return -1;
    }
}
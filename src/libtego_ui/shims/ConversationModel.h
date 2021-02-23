#pragma once

namespace shims
{
    class ContactUser;
    class ConversationModel : public QAbstractListModel
    {
        Q_OBJECT
        Q_ENUMS(MessageStatus)

        Q_PROPERTY(shims::ContactUser* contact READ contact WRITE setContact NOTIFY contactChanged)
        Q_PROPERTY(int unreadCount READ getUnreadCount RESET resetUnreadCount NOTIFY unreadCountChanged)
    public:
        ConversationModel(QObject *parent = 0);

        enum {
            TimestampRole = Qt::UserRole,
            IsOutgoingRole,
            StatusRole,
            SectionRole,
            TimespanRole,
            TypeRole,
            TransferRole,
        };

        enum MessageStatus {
            None,
            Received,
            Queued,
            Sending,
            Delivered,
            Error
        };

        enum MessageDataType
        {
            InvalidMessage = -1,
            TextMessage,
            TransferMessage,
        };

        enum TransferStatus
        {
            InvalidTransfer,
            Pending,
            InProgress,
            Cancelled,
            Finished,
        };
        Q_ENUM(TransferStatus);

        // impl QAbstractListModel
        virtual QHash<int,QByteArray> roleNames() const;
        virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
        virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

        shims::ContactUser *contact() const;
        void setContact(shims::ContactUser *contact);
        int getUnreadCount() const;
        Q_INVOKABLE void resetUnreadCount();

        void sendFile();
        void attachmentRequestAcknowledged(tego_attachment_id_t attachmentId, bool accepted);
        // cancelAttachmentTransfer neeeds to use a Qt type since it is invokable from QML
        static_assert(std::is_same_v<quint32, tego_attachment_id_t>);
        Q_INVOKABLE void cancelAttachmentTransfer(quint32 attachmentId);
        void updateAttachmentTransferProgress(tego_attachment_id_t attachmentId, qint64 bytesTransferred);
        void finishAttachmentTransfer(tego_attachment_id_t attachmentId);

        void messageReceived(tego_message_id_t messageId, QDateTime timestamp, const QString& text);
        void messageAcknowledged(tego_message_id_t messageId, bool accepted);

    public slots:
        void sendMessage(const QString &text);
        void clear();

    signals:
        void contactChanged();
        void unreadCountChanged(int prevCount, int currentCount);
    private:
        void setUnreadCount(int count);

        shims::ContactUser* contactUser = nullptr;

        struct MessageData
        {
            MessageDataType type = InvalidMessage;
            QString text = {};
            QDateTime time = {};
            tego_message_id_t identifier = 0;
            MessageStatus status = None;
            quint8 attemptCount = 0;
            // file transfer data
            QString fileName = {};
            qint64 fileSize = 0;
            QString fileHash = {};
            qint64 bytesTransferred = 0;
            tego_attachment_direction_t transferDirection = tego_attachment_direction_sending;
            TransferStatus transferStatus = InvalidTransfer;
        };

        QList<MessageData> messages;
        int unreadCount = 0;

        int indexOfIdentifier(tego_message_id_t messageId, bool isOutgoing) const;
    };
}
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
            Rejected,
            InProgress,
            Cancelled,
            Finished,
        };
        Q_ENUM(TransferStatus);

        enum TransferDirection
        {
            InvalidDirection,
            Uploading,
            Downloading,
        };
        Q_ENUM(TransferDirection);

        // impl QAbstractListModel
        virtual QHash<int,QByteArray> roleNames() const;
        virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
        virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

        shims::ContactUser *contact() const;
        void setContact(shims::ContactUser *contact);
        int getUnreadCount() const;
        Q_INVOKABLE void resetUnreadCount();

        void sendFile();
        // cancelAttachmentTransfer neeeds to use a Qt type since it is invokable from QML
        static_assert(std::is_same_v<quint32, tego_attachment_id_t>);
        Q_INVOKABLE void tryAcceptAttachmentTransfer(quint32 attachmentId);
        Q_INVOKABLE void cancelAttachmentTransfer(quint32 attachmentId);

        void attachmentRequestReceived(tego_attachment_id_t attachmentId, QString fileName, QString fileHash, quint64 fileSize);
        void attachmentRequestAcknowledged(tego_attachment_id_t attachmentId, bool accepted);
        void attachmentRequestResponded(tego_attachment_id_t attachmentId, tego_attachment_response_t response);
        void attachmentRequestProgressUpdated(tego_attachment_id_t attachmentId, quint64 bytesTransferred);
        void attachmentRequestCompleted(tego_attachment_id_t attachmentId);
        void attachmentRequestCancelled(tego_attachment_id_t attachmentId);

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
            static_assert(std::is_same_v<quint32, tego_attachment_id_t>);
            static_assert(std::is_same_v<quint32, tego_message_id_t>);
            quint32 identifier = 0;
            MessageStatus status = None;
            quint8 attemptCount = 0;
            // file transfer data
            QString fileName = {};
            qint64 fileSize = 0;
            QString fileHash = {};
            quint64 bytesTransferred = 0;
            TransferDirection transferDirection = InvalidDirection;;
            TransferStatus transferStatus = InvalidTransfer;
        };

        QList<MessageData> messages;
        int unreadCount = 0;

        void emitDataChanged(int row);
        int indexOfMessage(quint32 identifier) const;
        int indexOfOutgoingMessage(quint32 identifier) const;
        int indexOfIncomingMessage(quint32 identifier) const;
    };
}
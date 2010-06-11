/* TorIM - http://gitorious.org/torim
 * Copyright (C) 2010, John Brooks <special@dereferenced.net>
 *
 * TorIM is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with TorIM. If not, see http://www.gnu.org/licenses/
 */

#include "ProtocolSocket.h"
#include "ProtocolManager.h"
#include "ProtocolCommand.h"
#include "CommandHandler.h"
#include "IncomingSocket.h"
#include "tor/TorControlManager.h"
#include <QNetworkProxy>
#include <QtEndian>

/* Create with an established, authenticated connection */
ProtocolSocket::ProtocolSocket(QTcpSocket *s, ProtocolManager *m)
    : QObject(m), manager(m), socket(s), nextCommandId(0), active(true), authPending(false), authFinished(true)
{
    Q_ASSERT(isConnected());

    socket->setParent(this);
    setupSocket();
}

/* Create a new outgoing connection */
ProtocolSocket::ProtocolSocket(ProtocolManager *m)
    : QObject(m), manager(m), socket(new QTcpSocket(this)), nextCommandId(0), active(false), authPending(false),
      authFinished(false)
{
    connect(socket, SIGNAL(connected()), this, SLOT(sendAuth()));
    connect(this, SIGNAL(socketReady()), this, SLOT(flushCommands()));
    setupSocket();
}

void ProtocolSocket::setupSocket()
{
    connect(socket, SIGNAL(readyRead()), this, SLOT(read()));
    connect(socket, SIGNAL(disconnected()), this, SLOT(socketDisconnected()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(socketDisconnected()));
}

bool ProtocolSocket::isConnected() const
{
    return (authFinished && socket->state() == QAbstractSocket::ConnectedState);
}

bool ProtocolSocket::isConnecting() const
{
    return (socket->state() != QAbstractSocket::UnconnectedState && socket->state() != QAbstractSocket::ClosingState
            && !isConnected());
}

void ProtocolSocket::connectToHost(const QString &host, quint16 port)
{
    if (isConnected() && socket->peerName() == host && socket->peerPort() == port)
        return;

    socket->abort();
    active = true;

    if (!torManager->isSocksReady())
    {
        /* Can't make any connection; behave as if the connection attempt failed.
         * Many things should handle this situation prior to this function anyway. */
        socketDisconnected();
        return;
    }

    socket->setProxy(torManager->connectionProxy());
    socket->connectToHost(host, port);
}

void ProtocolSocket::abort()
{
    socket->abort();
}

void ProtocolSocket::abortConnectionAttempt()
{
    if (!isConnecting())
        return;

    /* We need to ensure that socketDisconnected is called once even if there wasn't technically a
     * connection yet (as it handles errors too). */

    socket->blockSignals(true);
    socket->abort();
    socket->blockSignals(false);

    socketDisconnected();
}

void ProtocolSocket::sendAuth()
{
    Q_ASSERT(!authPending && !authFinished);

    QByteArray intro = IncomingSocket::introData(0x00);

    QByteArray secret = manager->secret();
    Q_ASSERT(secret.size() == 16);

    if (secret.size() != 16)
    {
        int f = secret.size();
        secret.resize(16);
        memset(secret.data() + f, 0, 16 - f);
    }

    intro.append(secret);

    qint64 re = socket->write(intro);
    Q_ASSERT(re == intro.size());

    authPending = true;
}

void ProtocolSocket::flushCommands()
{
    while (!commandQueue.isEmpty())
        socket->write(commandQueue.takeFirst()->commandBuffer);
}

quint16 ProtocolSocket::getIdentifier()
{
    if (!nextCommandId)
    {
        Q_ASSERT(pendingCommands.isEmpty());

        /* Start with a random ID; technically not necessary, but still worth doing */
        nextCommandId = (qrand() % 65535) + 1;
    }

    /* Wraparound on unsigned integer overflow is well-defined, and we rely on it here. 0 is not a valid ID. */

    while (pendingCommands.contains(nextCommandId) || !nextCommandId)
        ++nextCommandId;

    quint16 re = nextCommandId;

    if (!++nextCommandId)
        nextCommandId++;

    return re;
}

void ProtocolSocket::sendCommand(ProtocolCommand *command)
{
    Q_ASSERT(!pendingCommands.contains(command->identifier()));

    pendingCommands.insert(command->identifier(), command);

    if (!isConnected())
    {
        qDebug() << "Added command to queue";
        commandQueue.append(command);
        return;
    }

    /* TODO Use the command queue even when connected, enough to allow tracking of sent status
     * without impacting performance (i.e. still optimal use of the buffer). */

    Q_ASSERT(commandQueue.isEmpty());
    qint64 re = socket->write(command->commandBuffer);
    Q_ASSERT(re == command->commandBuffer.size());

    qDebug() << "Wrote command:" << command->commandBuffer.toHex();
}

void ProtocolSocket::read()
{
    qDebug() << "Socket readable";

    qint64 available = socket->bytesAvailable();

    if (available && authPending && !authFinished)
    {
        if (available < 2)
            return;

        char reply[2];
        qint64 re = socket->read(reply, 2);
        Q_ASSERT(re == 2);

        if (reply[0] != protocolVersion)
        {
            qDebug() << "Outgoing socket rejected: Version negotiation failure";
            socket->close();
            return;
        }

        if (reply[1] != 0x00)
        {
            qDebug() << "Outgoing socket rejected: Authentication failure, code" << hex << (int)reply[1];
            socket->close();
            return;
        }

        authPending = false;
        authFinished = true;

        /* This will take care of flushing commands as well */
        emit socketReady();

        available -= 2;
    }

    while (available >= 6)
    {
        quint16 msgLength;
        if (socket->peek(reinterpret_cast<char*>(&msgLength), sizeof(msgLength)) < 2)
            return;

        msgLength = qFromBigEndian(msgLength);
        if (!msgLength)
            qFatal("Unbuffered protocol replies are not implemented");

        /* Message length is one more than the actual data length, and does not include the header. */
        msgLength--;
        if ((available - 6) < msgLength)
            break;

        QByteArray data;
        data.resize(msgLength + 6);

        qint64 re = socket->read(data.data(), msgLength + 6);
        Q_ASSERT(re == msgLength + 6);

        if (isReply(data[3]))
        {
            quint16 identifier = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(data.constData())+4);
            QHash<quint16,ProtocolCommand*>::Iterator it = pendingCommands.find(identifier);

            if (it != pendingCommands.end())
            {
                (*it)->processReply(data[3], reinterpret_cast<const uchar*>(data.constData())+6, msgLength);
                if (isFinal(data[3]))
                {
                    /* Duplicated in socketDisconnected() */
                    qDebug() << "Received final reply for identifier" << identifier;
                    emit (*it)->commandFinished();
                    (*it)->deleteLater();
                    pendingCommands.erase(it);
                }
            }
        }
        else
        {
            CommandHandler handler(manager->user, socket, reinterpret_cast<const uchar*>(data.constData()),
                                   msgLength + 6);
        }

        available -= msgLength + 6;
    }
}

void ProtocolSocket::socketDisconnected()
{
    if (!active)
        return;

    active = false;

    if (authFinished && !isConnecting())
        emit disconnected();
    else
        emit connectFailed();

    nextCommandId = 0;
    authFinished = authPending = false;

    /* Send failure replies for all pending commands */
    for (QHash<quint16,ProtocolCommand*>::Iterator it = pendingCommands.begin(); it != pendingCommands.end(); ++it)
    {
        (*it)->processReply(ProtocolCommand::ConnectionError, 0, 0);
        emit (*it)->commandFinished();
        (*it)->deleteLater();
    }

    for (QQueue<ProtocolCommand*>::Iterator it = commandQueue.begin(); it != commandQueue.end(); ++it)
    {
        (*it)->processReply(ProtocolCommand::ConnectionError, 0, 0);
        emit (*it)->commandFinished();
        (*it)->deleteLater();
    }

    pendingCommands.clear();
    commandQueue.clear();
}

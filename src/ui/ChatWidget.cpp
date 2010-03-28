#include "ChatWidget.h"
#include "core/ContactUser.h"
#include "protocol/ChatMessageCommand.h"
#include <QBoxLayout>
#include <QTextEdit>
#include <QLineEdit>
#include <QDateTime>
#include <QTextDocument>
#include <QLabel>
#include <QScrollBar>

ChatWidget::ChatWidget(ContactUser *u, QWidget *parent)
	: QWidget(parent), user(u)
{
	QBoxLayout *layout = new QVBoxLayout(this);
	layout->setMargin(0);

	createTextArea();
	layout->addWidget(textArea);

	createTextInput();
//	layout->addWidget(textInput);

	appendChatMessage(QDateTime::currentDateTime(), 0, "I wrote some text!");
	appendChatMessage(QDateTime::currentDateTime().addSecs(35), user, "And I replied to it.");

	QBoxLayout *testLayout = new QHBoxLayout;
	layout->addLayout(testLayout);

	testLayout->addStretch();

	QLabel *icon = new QLabel;
	icon->setPixmap(QPixmap("C:\\Users\\John\\Documents\\Icons\\Fugue\\icons-shadowless\\information.png"));
	testLayout->addWidget(icon);

	QLabel *test = new QLabel;
	test->setText("<b>Aaron</b> is not online. Your messages will be delivered as soon as possible.");

	QPalette p = test->palette();
	p.setColor(QPalette::WindowText, Qt::darkGray);
	test->setPalette(p);

	testLayout->addWidget(test);
	testLayout->addStretch();

	layout->addWidget(textInput);
}

void ChatWidget::createTextArea()
{
	textArea = new QTextEdit;
	textArea->setReadOnly(true);
	textArea->setFont(QFont("Calibri", 10));
}

void ChatWidget::createTextInput()
{
	textInput = new QLineEdit;
	textInput->setFont(QFont("Calibri", 10));

	connect(textInput, SIGNAL(returnPressed()), this, SLOT(sendInputMessage()));
}

void ChatWidget::sendInputMessage()
{
	QString text = textInput->text();
	if (text.isEmpty())
		return;
	textInput->clear();

	QDateTime when = QDateTime::currentDateTime();

	ChatMessageCommand *command = new ChatMessageCommand;
	command->send(user->conn(), when, text);

	appendChatMessage(when, NULL, text);
}

void ChatWidget::appendChatMessage(const QDateTime &when, ContactUser *from, const QString &text)
{
	QTextCursor cursor(textArea->document());
	cursor.movePosition(QTextCursor::End);

	if (!cursor.atBlockStart())
		cursor.insertBlock();

	bool light = false;
	if (!from && !user->isConnected())
		light = true; //alpha = 120;
#if 0
	{
		QTextBlockFormat blockFormat;
		blockFormat.setBackground(QColor(235, 235, 235));
		cursor.setBlockFormat(blockFormat);
	}
#endif

	/* Timestamp */
	QTextCharFormat tsFormat;
	tsFormat.setForeground(light ? QColor(200, 200, 202) : QColor(160, 160, 164));
	cursor.insertText(when.time().toString(QString("(HH:mm:ss) ")), tsFormat);

	/* Nickname */
	QTextCharFormat nickFormat;
	nickFormat.setFontWeight(QFont::Bold);
	if (!from)
		nickFormat.setForeground(light ? QColor(135, 185, 227) : QColor(0, 94, 173));
	else
		nickFormat.setForeground(light ? QColor(227, 135, 135) : QColor(174, 0, 0));

	QString nickname = from ? from->nickname() : tr("Me");

	cursor.insertText(nickname + QString(": "), nickFormat);

	/* Text */
	QTextCharFormat textFormat;
	textFormat.setForeground(light ? QColor(135, 135, 135) : QColor(0, 0, 0));
	cursor.insertText(text, textFormat);

	scrollToBottom();
}

void ChatWidget::scrollToBottom()
{
	textArea->verticalScrollBar()->setValue(textArea->verticalScrollBar()->maximum());
}

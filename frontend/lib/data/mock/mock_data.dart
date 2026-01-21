import '../models/chat.dart';
import '../models/group.dart';
import '../models/group_activity.dart';
import '../models/group_member.dart';
import '../models/message.dart';
import '../models/user.dart';

class MockData {
  static final List<Chat> chats = [
    Chat(
      id: '1',
      type: ChatType.direct,
      name: 'Alice Moore',
      avatar: 'AM',
      lastMessage: 'Hey! Did you see the new design?',
      lastMessageTime: DateTime.now().subtract(const Duration(minutes: 30)),
      unreadCount: 2,
      isOnline: true,
    ),
    Chat(
      id: '2',
      type: ChatType.group,
      name: 'Design Team',
      avatar: 'DT',
      lastMessage: "I'm uploading the files now.",
      lastMessageTime: DateTime.now().subtract(const Duration(hours: 2)),
      senderName: 'Bob',
      isOnline: false,
    ),
    Chat(
      id: '3',
      type: ChatType.direct,
      name: 'Mom',
      avatar: 'MO',
      lastMessage: 'Call me when you can.',
      lastMessageTime: DateTime.now().subtract(const Duration(days: 1)),
      isOnline: false,
    ),
    Chat(
      id: '4',
      type: ChatType.direct,
      name: 'John Wick',
      avatar: 'JW',
      lastMessage: 'Can we reschedule?',
      lastMessageTime: DateTime.now().subtract(const Duration(days: 2)),
      isOnline: false,
    ),
    Chat(
      id: '5',
      type: ChatType.group,
      name: 'Marketing Updates',
      avatar: 'MK',
      lastMessage: 'New campaign assets are live.',
      lastMessageTime: DateTime.now().subtract(const Duration(days: 7)),
      unreadCount: 5,
      isMuted: true,
      isOnline: false,
    ),
    Chat(
      id: '6',
      type: ChatType.direct,
      name: 'David Chen',
      avatar: 'DC',
      lastMessage: "Thanks for the update! Let's talk soo...",
      lastMessageTime: DateTime.now().subtract(const Duration(days: 14)),
      isOnline: false,
    ),
    Chat(
      id: '7',
      type: ChatType.direct,
      name: 'Sarah Connor',
      avatar: 'SC',
      lastMessage: 'The meeting is confirmed.',
      lastMessageTime: DateTime.now().subtract(const Duration(days: 30)),
      isOnline: false,
    ),
  ];

  static final List<Message> messages = [
    Message(
      id: '1',
      chatId: '1',
      senderId: '1',
      content: 'Hey! Did you check out the new zaply update?',
      timestamp: DateTime.now().subtract(const Duration(minutes: 35)),
      status: MessageStatus.read,
      isOwn: false,
      readBy: const ['1', 'me'],
      reactions: const {'👍': ['me']},
    ),
    Message(
      id: '2',
      chatId: '1',
      senderId: 'me',
      content: 'Yeah! The interface is super smooth. Love the dark mode.',
      timestamp: DateTime.now().subtract(const Duration(minutes: 33)),
      status: MessageStatus.read,
      isOwn: true,
      readBy: const ['me', '1'],
    ),
    Message(
      id: '3',
      chatId: '1',
      senderId: 'me',
      content: 'Are we meeting tomorrow?',
      timestamp: DateTime.now().subtract(const Duration(minutes: 32)),
      status: MessageStatus.read,
      isOwn: true,
      readBy: const ['me', '1'],
    ),
    Message(
      id: '4',
      chatId: '1',
      senderId: '1',
      content: 'For sure. 2 PM works?',
      timestamp: DateTime.now().subtract(const Duration(minutes: 31)),
      status: MessageStatus.read,
      isOwn: false,
      readBy: const ['1', 'me'],
      isPinned: true,
    ),
  ];

  static final User currentUser = User(
    id: 'me',
    name: 'Current User',
    username: '@current_user',
    avatar: 'https://i.pravatar.cc/150?u=me',
    isOnline: true,
  );

  static final User chatUser = User(
    id: '1',
    name: 'Alice Wonderland',
    username: '@alice_wonderland',
    avatar: 'https://i.pravatar.cc/150?u=alice',
    isOnline: true,
  );

  static final User settingsUser = User(
    id: 'jessica',
    name: 'Jessica Davis',
    username: '@jess_davis',
    email: 'jessica.davis@zaply.in.net',
    avatar: 'https://i.pravatar.cc/150?u=jessica',
    isOnline: true,
  );

  static final List<User> users = [
    currentUser,
    chatUser,
    settingsUser,
    const User(
      id: 'bob',
      name: 'Bob Stone',
      username: '@bob',
      avatar: 'https://i.pravatar.cc/150?u=bob',
      isOnline: false,
    ),
    const User(
      id: 'sarah',
      name: 'Sarah Connor',
      username: '@sarah',
      avatar: 'https://i.pravatar.cc/150?u=sarah',
      isOnline: true,
    ),
    const User(
      id: 'david',
      name: 'David Chen',
      username: '@david',
      avatar: 'https://i.pravatar.cc/150?u=david',
      isOnline: false,
    ),
  ];

  static final List<Group> groups = [
    Group(
      id: '2',
      name: 'Design Team',
      description: 'Design discussions and file handoffs.',
      avatar: 'DT',
      createdBy: 'bob',
      members: [
        GroupMember(userId: 'bob', role: GroupRole.admin, joinedAt: DateTime(2025, 1, 1)),
        GroupMember(userId: 'me', role: GroupRole.member, joinedAt: DateTime(2025, 1, 2)),
        GroupMember(userId: '1', role: GroupRole.member, joinedAt: DateTime(2025, 1, 2)),
      ],
      activity: [
        GroupActivity(
          id: 'ga1',
          event: 'group_created',
          actorId: 'bob',
          timestamp: DateTime.now().subtract(const Duration(days: 10)),
          meta: const {'name': 'Design Team'},
        ),
      ],
    ),
    Group(
      id: '5',
      name: 'Marketing Updates',
      description: 'Announcements and weekly updates.',
      avatar: 'MK',
      createdBy: 'sarah',
      notificationsMuted: true,
      members: [
        GroupMember(userId: 'sarah', role: GroupRole.admin, joinedAt: DateTime(2025, 1, 5)),
        GroupMember(userId: 'me', role: GroupRole.member, joinedAt: DateTime(2025, 1, 6)),
      ],
      activity: const [],
    ),
  ];
}
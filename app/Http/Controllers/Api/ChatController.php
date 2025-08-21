<?php

namespace App\Http\Controllers\Api;

use App\Events\ChatMessageSent;
use App\Events\UserJoinedChat;
use App\Events\UserLeftChat;
use App\Http\Controllers\Controller;
use App\Models\ChatMessage;
use App\Models\ChatParticipant;
use App\Models\ChatRoom;
use App\Models\User;
use App\Traits\HttpResponses;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class ChatController extends Controller
{
    use HttpResponses;

    /**
     * Get global chat room info
     */
    public function getGlobalChatInfo()
    {
        $globalRoom = ChatRoom::getGlobalRoom();
        
        if (!$globalRoom) {
            $globalRoom = ChatRoom::createGlobalRoom();
        }

        $onlineUsers = $globalRoom->onlineParticipants()
            ->with('user:id,user_name,phone')
            ->get()
            ->map(function ($participant) {
                return [
                    'id' => $participant->user->id,
                    'name' => $participant->user->user_name,
                    'phone' => $participant->user->phone,
                    'last_seen' => $participant->last_seen_at
                ];
            });

        return $this->success([
            'room' => [
                'id' => $globalRoom->id,
                'name' => $globalRoom->name,
                'description' => $globalRoom->description,
                'is_global' => $globalRoom->is_global
            ],
            'online_users' => $onlineUsers,
            'online_count' => $onlineUsers->count()
        ], 'Global chat info retrieved successfully');
    }

    /**
     * Join global chat room
     */
    public function joinGlobalChat()
    {
        $user = Auth::user();
        $globalRoom = ChatRoom::getGlobalRoom();
        
        if (!$globalRoom) {
            $globalRoom = ChatRoom::createGlobalRoom();
        }

        // Create or update participant
        $participant = ChatParticipant::updateOrCreate(
            [
                'user_id' => $user->id,
                'chat_room_id' => $globalRoom->id
            ],
            [
                'is_online' => true,
                'last_seen_at' => now(),
                'joined_at' => now(),
                'left_at' => null
            ]
        );

        $participant->markAsOnline();

        // Broadcast user joined event
        broadcast(new UserJoinedChat($user, $globalRoom->id))->toOthers();

        // Send system message
        $this->sendSystemMessage($globalRoom->id, "{$user->user_name} joined the chat");

        return $this->success([
            'room_id' => $globalRoom->id,
            'joined_at' => $participant->joined_at
        ], 'Successfully joined global chat');
    }

    /**
     * Leave global chat room
     */
    public function leaveGlobalChat()
    {
        $user = Auth::user();
        $globalRoom = ChatRoom::getGlobalRoom();

        if ($globalRoom) {
            $participant = ChatParticipant::where('user_id', $user->id)
                ->where('chat_room_id', $globalRoom->id)
                ->first();

            if ($participant) {
                $participant->markAsOffline();

                // Broadcast user left event
                broadcast(new UserLeftChat($user, $globalRoom->id))->toOthers();

                // Send system message
                $this->sendSystemMessage($globalRoom->id, "{$user->user_name} left the chat");
            }
        }

        return $this->success(null, 'Successfully left global chat');
    }

    /**
     * Send message to global chat
     */
    public function sendMessage(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'message' => 'required|string|max:1000',
            'message_type' => 'nullable|string|in:text,image,file',
            'metadata' => 'nullable|array'
        ]);

        if ($validator->fails()) {
            return $this->error('Validation Error', $validator->errors()->first(), 422);
        }

        $user = Auth::user();
        $globalRoom = ChatRoom::getGlobalRoom();

        if (!$globalRoom) {
            return $this->error('Chat Error', 'Global chat room not found', 404);
        }

        // Check if user is participant
        $participant = ChatParticipant::where('user_id', $user->id)
            ->where('chat_room_id', $globalRoom->id)
            ->first();

        if (!$participant || !$participant->is_online) {
            return $this->error('Chat Error', 'You must join the chat first', 400);
        }

        try {
            DB::beginTransaction();

            // Create message
            $message = ChatMessage::create([
                'user_id' => $user->id,
                'chat_room_id' => $globalRoom->id,
                'message' => $request->message,
                'message_type' => $request->message_type ?? 'text',
                'metadata' => $request->metadata
            ]);

            // Update participant last seen
            $participant->updateLastSeen();

            DB::commit();

            // Broadcast message
            broadcast(new ChatMessageSent($message))->toOthers();

            return $this->success([
                'message_id' => $message->id,
                'sent_at' => $message->created_at
            ], 'Message sent successfully');

        } catch (\Exception $e) {
            DB::rollback();
            Log::error('Error sending chat message: ' . $e->getMessage());
            return $this->error('Server Error', 'Failed to send message', 500);
        }
    }

    /**
     * Get chat messages
     */
    public function getMessages(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'page' => 'nullable|integer|min:1',
            'limit' => 'nullable|integer|min:1|max:100',
            'before_id' => 'nullable|integer'
        ]);

        if ($validator->fails()) {
            return $this->error('Validation Error', $validator->errors()->first(), 422);
        }

        $globalRoom = ChatRoom::getGlobalRoom();
        
        if (!$globalRoom) {
            return $this->error('Chat Error', 'Global chat room not found', 404);
        }

        $page = $request->input('page', 1);
        $limit = $request->input('limit', 50);
        $beforeId = $request->input('before_id');

        $query = ChatMessage::with('user:id,user_name,phone')
            ->where('chat_room_id', $globalRoom->id)
            ->notDeleted()
            ->orderBy('created_at', 'desc');

        if ($beforeId) {
            $query->where('id', '<', $beforeId);
        }

        $messages = $query->paginate($limit, ['*'], 'page', $page);

        $formattedMessages = $messages->getCollection()->map(function ($message) {
            return [
                'id' => $message->id,
                'user_id' => $message->user_id,
                'user_name' => $message->user->user_name,
                'user_phone' => $message->user->phone,
                'message' => $message->formatted_message,
                'message_type' => $message->message_type,
                'metadata' => $message->metadata,
                'is_edited' => $message->is_edited,
                'is_deleted' => $message->is_deleted,
                'created_at' => $message->created_at->toISOString(),
                'updated_at' => $message->updated_at->toISOString(),
            ];
        });

        return $this->success([
            'messages' => $formattedMessages,
            'pagination' => [
                'current_page' => $messages->currentPage(),
                'last_page' => $messages->lastPage(),
                'per_page' => $messages->perPage(),
                'total' => $messages->total(),
                'has_more' => $messages->hasMorePages()
            ]
        ], 'Messages retrieved successfully');
    }

    /**
     * Update user's online status
     */
    public function updateOnlineStatus()
    {
        $user = Auth::user();
        $globalRoom = ChatRoom::getGlobalRoom();

        if ($globalRoom) {
            $participant = ChatParticipant::where('user_id', $user->id)
                ->where('chat_room_id', $globalRoom->id)
                ->first();

            if ($participant) {
                $participant->updateLastSeen();
            }
        }

        return $this->success(null, 'Online status updated');
    }

    /**
     * Get online users
     */
    public function getOnlineUsers()
    {
        $globalRoom = ChatRoom::getGlobalRoom();
        
        if (!$globalRoom) {
            return $this->success(['users' => []], 'No online users');
        }

        $onlineUsers = $globalRoom->onlineParticipants()
            ->with('user:id,user_name,phone')
            ->get()
            ->map(function ($participant) {
                return [
                    'id' => $participant->user->id,
                    'name' => $participant->user->user_name,
                    'phone' => $participant->user->phone,
                    'last_seen' => $participant->last_seen_at->toISOString()
                ];
            });

        return $this->success([
            'users' => $onlineUsers,
            'count' => $onlineUsers->count()
        ], 'Online users retrieved successfully');
    }

    /**
     * Send system message
     */
    private function sendSystemMessage($roomId, $message)
    {
        try {
            $systemMessage = ChatMessage::create([
                'user_id' => 1, // System user ID
                'chat_room_id' => $roomId,
                'message' => $message,
                'message_type' => 'system'
            ]);

            broadcast(new ChatMessageSent($systemMessage))->toOthers();
        } catch (\Exception $e) {
            Log::error('Error sending system message: ' . $e->getMessage());
        }
    }
}

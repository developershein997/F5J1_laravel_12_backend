<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ChatParticipant extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'chat_room_id',
        'is_online',
        'last_seen_at',
        'joined_at',
        'left_at'
    ];

    protected $casts = [
        'is_online' => 'boolean',
        'last_seen_at' => 'datetime',
        'joined_at' => 'datetime',
        'left_at' => 'datetime'
    ];

    /**
     * Get the user
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the chat room
     */
    public function chatRoom(): BelongsTo
    {
        return $this->belongsTo(ChatRoom::class);
    }

    /**
     * Mark user as online
     */
    public function markAsOnline()
    {
        $this->update([
            'is_online' => true,
            'last_seen_at' => now(),
            'joined_at' => $this->joined_at ?? now(),
            'left_at' => null
        ]);
    }

    /**
     * Mark user as offline
     */
    public function markAsOffline()
    {
        $this->update([
            'is_online' => false,
            'last_seen_at' => now(),
            'left_at' => now()
        ]);
    }

    /**
     * Update last seen timestamp
     */
    public function updateLastSeen()
    {
        $this->update(['last_seen_at' => now()]);
    }

    /**
     * Check if user is currently online
     */
    public function isCurrentlyOnline()
    {
        return $this->is_online && $this->last_seen_at && 
               $this->last_seen_at->diffInMinutes(now()) < 5;
    }
}

<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ChatMessage extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'chat_room_id',
        'message',
        'message_type',
        'metadata',
        'is_edited',
        'edited_at',
        'is_deleted',
        'deleted_at'
    ];

    protected $casts = [
        'metadata' => 'array',
        'is_edited' => 'boolean',
        'edited_at' => 'datetime',
        'is_deleted' => 'boolean',
        'deleted_at' => 'datetime'
    ];

    /**
     * Get the user who sent this message
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the chat room this message belongs to
     */
    public function chatRoom(): BelongsTo
    {
        return $this->belongsTo(ChatRoom::class);
    }

    /**
     * Scope to get only non-deleted messages
     */
    public function scopeNotDeleted($query)
    {
        return $query->where('is_deleted', false);
    }

    /**
     * Scope to get messages by type
     */
    public function scopeByType($query, $type)
    {
        return $query->where('message_type', $type);
    }

    /**
     * Get formatted message for display
     */
    public function getFormattedMessageAttribute()
    {
        if ($this->is_deleted) {
            return '[Message deleted]';
        }

        return $this->message;
    }

    /**
     * Check if message is from system
     */
    public function isSystemMessage()
    {
        return $this->message_type === 'system';
    }

    /**
     * Check if message is from user
     */
    public function isUserMessage()
    {
        return $this->message_type === 'text';
    }
}

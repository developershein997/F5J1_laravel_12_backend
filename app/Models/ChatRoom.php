<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ChatRoom extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'description',
        'is_active',
        'is_global',
        'max_participants'
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'is_global' => 'boolean',
        'max_participants' => 'integer'
    ];

    /**
     * Get all messages in this chat room
     */
    public function messages(): HasMany
    {
        return $this->hasMany(ChatMessage::class);
    }

    /**
     * Get all participants in this chat room
     */
    public function participants(): HasMany
    {
        return $this->hasMany(ChatParticipant::class);
    }

    /**
     * Get online participants
     */
    public function onlineParticipants()
    {
        return $this->participants()->where('is_online', true);
    }

    /**
     * Get the global chat room
     */
    public static function getGlobalRoom()
    {
        return static::where('is_global', true)->where('is_active', true)->first();
    }

    /**
     * Create global chat room if it doesn't exist
     */
    public static function createGlobalRoom()
    {
        return static::firstOrCreate(
            ['is_global' => true],
            [
                'name' => 'Global Chat',
                'description' => 'Global chat room for all players',
                'is_active' => true,
                'is_global' => true
            ]
        );
    }
}

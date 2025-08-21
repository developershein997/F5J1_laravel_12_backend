<?php

namespace App\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Carbon\Carbon;


class PushBet extends Model
{
    use HasFactory;

    protected $table = 'push_bets';

    protected $fillable = [
        'member_account',
        'currency',
        'product_code',
        'game_code',
        'game_type',
        'wager_code',
        'wager_type',
        'wager_status',
        'bet_amount',
        'valid_bet_amount',
        'prize_amount',
        'tip_amount',
        'created_at_provider',
        'settled_at',
        'meta',
    ];

    // protected $casts = [
    //     'meta' => 'array',
    //     'settled_at' => 'datetime',
    //     'created_at_provider' => 'datetime',
    // ];

    protected $casts = [
        'meta' => 'array',
        'settled_at' => 'datetime',
        'created_at_provider' => 'datetime',
        'product_code' => 'integer',
        'game_code' => 'string',
        'bet_amount' => 'decimal:2',
        'valid_bet_amount' => 'decimal:2',
        'prize_amount' => 'decimal:2',
        'tip_amount' => 'decimal:2',
    ];

    // PlaceBet.php
    public function user()
    {
        return $this->belongsTo(User::class, 'member_account', 'user_name');
    }

    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            $model->created_at = Carbon::now('Asia/Yangon');
            $model->updated_at = Carbon::now('Asia/Yangon');
        });

        static::updating(function ($model) {
            $model->updated_at = Carbon::now('Asia/Yangon');
        });
    }
}

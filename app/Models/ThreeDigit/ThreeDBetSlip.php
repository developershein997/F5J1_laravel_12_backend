<?php

namespace App\Models\ThreeDigit;

use App\Models\ThreeDigit\ThreeDBet;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ThreeDBetSlip extends Model
{
    use HasFactory;

    protected $table = 'three_d_bet_slips';

    protected $fillable = [
        'slip_no',
        'user_id',
        'player_name',
        'agent_id',
        'total_bet_amount',
        'draw_session',
        'status',
        'game_date',
        'game_time',
        'before_balance',
        'after_balance',
    ];

    protected $casts = [
        'total_bet_amount' => 'decimal:2',
        'before_balance' => 'decimal:2',
        'after_balance' => 'decimal:2',
        'game_date' => 'date',
        'game_time' => 'datetime',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function agent()
    {
        return $this->belongsTo(User::class, 'agent_id');
    }

    public function threeDBets()
    {
        return $this->hasMany(ThreeDBet::class, 'slip_id', 'id');
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

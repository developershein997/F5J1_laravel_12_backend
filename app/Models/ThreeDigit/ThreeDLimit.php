<?php

namespace App\Models\ThreeDigit;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ThreeDLimit extends Model
{
    use HasFactory;

    protected $table = 'three_d_limits';

    protected $fillable = [
        'min_bet_amount',
        'max_bet_amount',
        'max_total_bet',
        'payout_multiplier',
        'is_active',
        'description',
    ];

    protected $casts = [
        'min_bet_amount' => 'decimal:2',
        'max_bet_amount' => 'decimal:2',
        'max_total_bet' => 'decimal:2',
        'payout_multiplier' => 'decimal:2',
        'is_active' => 'boolean',
    ];

    /**
     * Get the active limit settings
     */
    public static function getActiveLimit()
    {
        return static::where('is_active', true)->latest()->first();
    }

    /**
     * Check if bet amount is within limits
     */
    public function isBetAmountValid($amount)
    {
        return $amount >= $this->min_bet_amount && $amount <= $this->max_bet_amount;
    }

    /**
     * Check if total bet amount is within limits
     */
    public function isTotalBetValid($totalAmount)
    {
        return $totalAmount <= $this->max_total_bet;
    }

    /**
     * Calculate potential payout
     */
    public function calculatePayout($betAmount)
    {
        return $betAmount * $this->payout_multiplier;
    }
}

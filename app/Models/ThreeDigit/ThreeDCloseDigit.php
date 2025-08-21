<?php

namespace App\Models\ThreeDigit;

use App\Models\ThreeDigit\ThreeDBet;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ThreeDCloseDigit extends Model
{
    use HasFactory;

    protected $table = 'three_d_close_digits';

    protected $fillable = [
        'close_digit',
        'status',
    ];

    protected $casts = [
        'status' => 'boolean',
    ];

    /**
     * Get the 3D bets associated with this close digit
     */
    public function threeDBets()
    {
        return $this->hasMany(ThreeDBet::class, 'bet_number', 'close_digit');
    }

    /**
     * Scope for open digits (status = true)
     */
    public function scopeOpen($query)
    {
        return $query->where('status', true);
    }

    /**
     * Scope for closed digits (status = false)
     */
    public function scopeClosed($query)
    {
        return $query->where('status', false);
    }

    /**
     * Get all open digits
     */
    public static function getOpenDigits()
    {
        return self::open()->orderBy('close_digit', 'asc')->get();
    }

    /**
     * Get all closed digits
     */
    public static function getClosedDigits()
    {
        return self::closed()->orderBy('close_digit', 'asc')->get();
    }

    /**
     * Check if a specific digit is open
     */
    public static function isDigitOpen($digit)
    {
        $digit = str_pad($digit, 3, '0', STR_PAD_LEFT);
        return self::where('close_digit', $digit)->where('status', true)->exists();
    }

    /**
     * Check if a specific digit is closed
     */
    public static function isDigitClosed($digit)
    {
        $digit = str_pad($digit, 3, '0', STR_PAD_LEFT);
        return self::where('close_digit', $digit)->where('status', false)->exists();
    }
}

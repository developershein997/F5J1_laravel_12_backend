<?php

namespace App\Models\ThreeDigit;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ThreeDDrawSession extends Model
{
    use HasFactory;

    protected $table = 'three_d_draw_sessions';
    
    protected $fillable = [
        'draw_session',
        'is_open',
        'notes',
    ];

    protected $casts = [
        'is_open' => 'boolean',
    ];

    /**
     * Scope for open draw sessions
     */
    public function scopeOpen($query)
    {
        return $query->where('is_open', true);
    }

    /**
     * Scope for closed draw sessions
     */
    public function scopeClosed($query)
    {
        return $query->where('is_open', false);
    }

    /**
     * Check if a draw session is open for betting
     */
    public static function isSessionOpen(string $drawSession): bool
    {
        $session = self::where('draw_session', $drawSession)->first();
        
        if ($session) {
            return $session->is_open;
        }
        
        // If not in database, check if it's the current session
        $currentDate = \Carbon\Carbon::now();
        $sessionDate = \Carbon\Carbon::parse($drawSession);
        
        // Only current session is open by default, others are closed
        return $sessionDate->eq($currentDate->startOfDay());
    }

    /**
     * Get all draw sessions with their status
     */
    public static function getAllSessionsWithStatus(array $drawSessions): array
    {
        $sessionStatuses = self::pluck('is_open', 'draw_session')->toArray();
        
        return collect($drawSessions)->map(function ($session) use ($sessionStatuses) {
            return [
                'draw_session' => $session,
                'is_open' => $sessionStatuses[$session] ?? true, // Default to open
            ];
        })->toArray();
    }
}

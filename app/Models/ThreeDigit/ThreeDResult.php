<?php

namespace App\Models\ThreeDigit;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ThreeDResult extends Model
{
    use HasFactory;

    protected $table = 'three_d_results';

    protected $fillable = [
        'win_number',
        'draw_session',
        'result_date',
        'result_time',
        'break_group',
        'status',
        'notes',
    ];

    protected $casts = [
        'result_date' => 'date',
        'result_time' => 'datetime',
        'break_group' => 'integer',
    ];

    /**
     * Calculate break group (sum of digits)
     */
    public function calculateBreakGroup()
    {
        $digits = str_split($this->win_number);
        return array_sum($digits);
    }

    /**
     * Scope for pending results
     */
    public function scopePending($query)
    {
        return $query->where('status', 'pending');
    }

    /**
     * Scope for declared results
     */
    public function scopeDeclared($query)
    {
        return $query->where('status', 'declared');
    }

    /**
     * Scope for completed results
     */
    public function scopeCompleted($query)
    {
        return $query->where('status', 'completed');
    }

    /**
     * Scope for today's results
     */
    public function scopeToday($query)
    {
        return $query->where('result_date', Carbon::today());
    }

    /**
     * Scope for specific draw session
     */
    public function scopeForDrawSession($query, $drawSession)
    {
        return $query->where('draw_session', $drawSession);
    }

    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            // Calculate break group if not set
            if (!$model->break_group) {
                $model->break_group = $model->calculateBreakGroup();
            }
        });
    }
}

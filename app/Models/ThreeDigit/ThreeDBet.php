<?php

namespace App\Models\ThreeDigit;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ThreeDBet extends Model
{
    use HasFactory;

    protected $table = 'three_d_bets';

    protected $primaryKey = 'id';

    public $timestamps = true;

    protected $fillable = [
        'user_id',
        'member_name',
        'agent_id',
        'bet_number',
        'bet_amount',
        'is_permutation',
        'permutation_amount',
        'break_group',
        'draw_session',
        'win_lose',
        'potential_payout',
        'bet_status',
        'bet_result',
        'prize_sent',
        'game_date',
        'game_time',
        'slip_id',
        'before_balance',
        'after_balance',
    ];

    protected $casts = [
        'bet_amount' => 'decimal:2',
        'permutation_amount' => 'decimal:2',
        'potential_payout' => 'decimal:2',
        'bet_status' => 'boolean',
        'win_lose' => 'boolean',
        'is_permutation' => 'boolean',
        'prize_sent' => 'boolean',
        'game_date' => 'date',
        'game_time' => 'datetime',
        'before_balance' => 'decimal:2',
        'after_balance' => 'decimal:2',
    ];

    /**
     * Get the user that placed the bet.
     */
    public function user()
    {
        return $this->belongsTo(User::class, 'user_id');
    }

    /**
     * Get the agent associated with the bet.
     */
    public function agent()
    {
        return $this->belongsTo(User::class, 'agent_id');
    }

    /**
     * Get the slip this bet belongs to.
     */
    public function slip()
    {
        return $this->belongsTo(ThreeDBetSlip::class, 'slip_id');
    }

    /**
     * Calculate break group (sum of digits)
     */
    public function calculateBreakGroup()
    {
        $digits = str_split($this->bet_number);
        return array_sum($digits);
    }

    /**
     * Generate all permutations of the bet number
     */
    public function generatePermutations()
    {
        $digits = str_split($this->bet_number);
        $permutations = [];
        
        // Generate all possible arrangements
        for ($i = 0; $i < 3; $i++) {
            for ($j = 0; $j < 3; $j++) {
                for ($k = 0; $k < 3; $k++) {
                    if ($i !== $j && $i !== $k && $j !== $k) {
                        $perm = $digits[$i] . $digits[$j] . $digits[$k];
                        if (!in_array($perm, $permutations)) {
                            $permutations[] = $perm;
                        }
                    }
                }
            }
        }
        
        return $permutations;
    }

    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            $model->game_date = Carbon::now('Asia/Yangon')->format('Y-m-d');
            $model->game_time = Carbon::now('Asia/Yangon')->format('H:i:s');
            $model->created_at = Carbon::now('Asia/Yangon');
            $model->updated_at = Carbon::now('Asia/Yangon');
            
            // Calculate break group if not set
            if (!$model->break_group) {
                $model->break_group = $model->calculateBreakGroup();
            }
        });

        static::updating(function ($model) {
            $model->updated_at = Carbon::now('Asia/Yangon');
        });
    }
}

<?php

namespace App\Services;

use App\Enums\DigitTransactionName;
use App\Models\ThreeDigit\ThreeDBet;
use App\Models\ThreeDigit\ThreeDBetSlip;
use App\Models\ThreeDigit\ThreeDLimit;
use App\Models\ThreeDigit\ThreeDCloseDigit;
use App\Models\ThreeDigit\ThreeDDrawSession;
use App\Models\User;
use App\Services\ThreeDDrawService;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class ThreeDPlayService
{
    protected $walletService;

    public function __construct(WalletService $walletService)
    {
        $this->walletService = $walletService;
    }

    /**
     * Handles the logic for placing a 3D bet using custom main_balance.
     *
     * @param  float  $totalBetAmount  The total sum of all individual bet amounts.
     * @param  array  $amounts  An array of individual bets, e.g., [['num' => '123', 'amount' => 100], ...].
     * @param  string  $drawSession  The draw session for the bet.
     * @return array|string Returns an array of over-limit digits, or a success message.
     *
     * @throws \Exception If authentication fails, limits are not set, or other issues occur.
     */
    public function play(float $totalBetAmount, array $amounts, string $drawSession)
    {
        /** @var User $user */
        $user = Auth::user();

        if (!$user) {
            throw new \Exception('User not authenticated.');
        }

        // Check if betting is open for this draw session
        if (!ThreeDDrawService::isBettingOpen($drawSession)) {
            throw new \Exception('Betting is currently closed for this draw session.');
        }

        // Check if draw session is open for betting
        if (!ThreeDDrawSession::isSessionOpen($drawSession)) {
            throw new \Exception('This draw session is closed for betting.');
        }

        $gameDate = Carbon::now()->format('Y-m-d');
        $gameTime = Carbon::now()->format('H:i:s');

        try {
            DB::beginTransaction();

            // Validate that totalBetAmount matches the sum of individual amounts
            $calculatedTotal = collect($amounts)->sum('amount');
            if ($calculatedTotal != $totalBetAmount) {
                $amountDetails = collect($amounts)->map(function($amount) {
                    return "Number {$amount['num']}: {$amount['amount']}";
                })->implode(', ');
                
                throw new \Exception("Total bet amount mismatch! You sent totalAmount: {$totalBetAmount}, but the sum of individual amounts is: {$calculatedTotal}. Amount details: {$amountDetails}");
            }

            $userPersonalLimit = $user->limit3 ?? null;
            Log::info('User personal 3D limit: '.($userPersonalLimit ?? 'Not Set'));

            $overallThreeDLimit = ThreeDLimit::getActiveLimit();
            if (!$overallThreeDLimit) {
                throw new ModelNotFoundException('Overall 3D limit (break) not set.');
            }
            $overallBreakAmount = $overallThreeDLimit->max_total_bet;
            Log::info("Overall 3D break limit: {$overallBreakAmount}");

            if ($user->wallet->balanceFloat < $totalBetAmount) {
                throw new \Exception('Insufficient funds in your main balance.');
            }

            $overLimitDigits = $this->checkAllLimits($amounts, $drawSession, $gameDate, $overallBreakAmount, $userPersonalLimit);
            if (!empty($overLimitDigits)) {
                return $overLimitDigits;
            }

            // Generate a unique slip number
            $slipNo = $this->generateUniqueSlipNumber();
            Log::info("Generated Slip No for batch: {$slipNo}");

            $beforeBalance = $user->wallet->balanceFloat;
            Log::info("Before withdrawal - User ID: {$user->id}, Balance: {$beforeBalance}, Total Bet Amount: {$totalBetAmount}");

            // Use proper wallet withdrawal instead of direct balance modification
            $this->walletService->withdraw($user, $totalBetAmount, DigitTransactionName::ThreeDigitBet, [
                'slip_no' => $slipNo,
                'draw_session' => $drawSession,
                'game_date' => $gameDate,
                'game_time' => $gameTime,
                'bet_details' => $amounts
            ]);

            // Refresh the user model to get the updated balance
            $user->refresh();

            $afterBalance = $user->wallet->balanceFloat;
            Log::info("After withdrawal - User ID: {$user->id}, Balance: {$afterBalance}, Expected Balance: " . ($beforeBalance - $totalBetAmount));
            
            if ($afterBalance != ($beforeBalance - $totalBetAmount)) {
                Log::warning("Balance mismatch detected! Expected: " . ($beforeBalance - $totalBetAmount) . ", Actual: {$afterBalance}");
            }

            $playerName = $user->user_name;
            $agentId = $user->agent_id;

            // Create the ThreeDBetSlip record first
            $threeDBetSlip = ThreeDBetSlip::create([
                'slip_no' => $slipNo,
                'user_id' => $user->id,
                'player_name' => $playerName,
                'agent_id' => $agentId,
                'total_bet_amount' => $totalBetAmount,
                'draw_session' => $drawSession,
                'status' => 'pending',
                'game_date' => $gameDate,
                'game_time' => $gameTime,
                'before_balance' => $beforeBalance,
                'after_balance' => $afterBalance,
            ]);

            foreach ($amounts as $betDetail) {
                $threeDigit = str_pad($betDetail['num'], 3, '0', STR_PAD_LEFT);
                $subAmount = $betDetail['amount'];

                ThreeDBet::create([
                    'user_id' => $user->id,
                    'member_name' => $user->user_name,
                    'agent_id' => $user->agent_id,
                    'bet_number' => $threeDigit,
                    'bet_amount' => $subAmount,
                    'is_permutation' => false,
                    'permutation_amount' => null,
                    'break_group' => array_sum(str_split($threeDigit)),
                    'draw_session' => $drawSession,
                    'win_lose' => false,
                    'potential_payout' => $subAmount * $overallThreeDLimit->payout_multiplier,
                    'bet_status' => false,
                    'bet_result' => null,
                    'prize_sent' => false,
                    'game_date' => $gameDate,
                    'game_time' => $gameTime,
                    'slip_id' => $threeDBetSlip->id,
                    'before_balance' => $beforeBalance,
                    'after_balance' => $afterBalance,
                ]);
            }

            DB::commit();

            return 'Bet placed successfully.';

        } catch (ModelNotFoundException $e) {
            DB::rollback();
            Log::error('Resource not found in ThreeDPlayService: '.$e->getMessage(), ['trace' => $e->getTraceAsString()]);

            return 'Required resource (e.g., 3D Limit) not found.';
        } catch (\Exception $e) {
            DB::rollback();
            Log::error('Error in ThreeDPlayService play method: '.$e->getMessage(), ['trace' => $e->getTraceAsString()]);

            return $e->getMessage();
        }
    }

    /**
     * Checks all limits (close digits, and total bet amount per digit).
     */
    protected function checkAllLimits(
        array $amounts,
        string $drawSession,
        string $gameDate,
        float $overallBreakAmount,
        ?float $userPersonalLimit
    ): array {
        $overLimitDigits = [];

        // Get closed 3D digits
        $closedThreeDigits = ThreeDCloseDigit::where('status', false)
            ->pluck('close_digit')
            ->map(fn ($digit) => str_pad($digit, 3, '0', STR_PAD_LEFT))
            ->unique()
            ->all();

        foreach ($amounts as $amount) {
            $threeDigit = str_pad($amount['num'], 3, '0', STR_PAD_LEFT);
            $subAmount = $amount['amount'];

            // Check if digit is closed
            if (in_array($threeDigit, $closedThreeDigits)) {
                $overLimitDigits[] = $threeDigit;
                continue;
            }

            // Check total bet amount for this digit across all users
            $totalBetAmountForThreeDigit = DB::table('three_d_bets')
                ->where('game_date', $gameDate)
                ->where('draw_session', $drawSession)
                ->where('bet_number', $threeDigit)
                ->sum('bet_amount');

            $projectedTotalBetAmount = $totalBetAmountForThreeDigit + $subAmount;

            if ($projectedTotalBetAmount > $overallBreakAmount) {
                $overLimitDigits[] = $threeDigit;
                continue;
            }

            // Check user's personal limit for this digit
            $userBetAmountOnThisDigit = DB::table('three_d_bets')
                ->where('user_id', Auth::id())
                ->where('game_date', $gameDate)
                ->where('draw_session', $drawSession)
                ->where('bet_number', $threeDigit)
                ->sum('bet_amount');

            $projectedUserBetAmount = $userBetAmountOnThisDigit + $subAmount;

            if ($userPersonalLimit !== null && $projectedUserBetAmount > $userPersonalLimit) {
                $overLimitDigits[] = $threeDigit;
                continue;
            }
        }

        return $overLimitDigits;
    }

    /**
     * Generates a unique slip number for 3D bets.
     */
    protected function generateUniqueSlipNumber(): string
    {
        $maxRetries = 20;
        $attempt = 0;

        do {
            $attempt++;

            $slipNo = $this->generateBaseSlipNumberWithCounter();

            // Check if this generated slip number already exists
            $exists = DB::table('three_d_bet_slips')->where('slip_no', $slipNo)->exists();

            if (!$exists) {
                return $slipNo;
            }

            Log::warning("3D Slip number collision detected (attempt {$attempt}): {$slipNo}");

            usleep(rand(100, 500));

            if ($attempt >= $maxRetries) {
                Log::critical("Failed to generate unique 3D slip number after {$maxRetries} attempts. Last attempt: {$slipNo}");
                throw new \Exception('Could not generate a unique slip number. Please try again.');
            }

        } while (true);
    }

    /**
     * Generates the base slip number for 3D bets.
     */
    private function generateBaseSlipNumberWithCounter(): string
    {
        $currentDate = Carbon::now()->format('Y-m-d');
        $currentTime = Carbon::now()->format('H:i:s');
        $customString = 'mk-3d';

        return DB::transaction(function () use ($currentDate, $currentTime, $customString) {
            // Get the current counter record or create it if it doesn't exist
            $counter = DB::table('slip_number_counters')
                ->lockForUpdate()
                ->where('id', 2) // Use ID 2 for 3D slips
                ->first();

            if (!$counter) {
                // Create counter for 3D if it doesn't exist
                DB::table('slip_number_counters')->insert([
                    'id' => 2,
                    'current_number' => 0,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
                $newNumber = 1;
            } else {
                $newNumber = $counter->current_number + 1;
                DB::table('slip_number_counters')
                    ->where('id', 2)
                    ->update(['current_number' => $newNumber]);
            }

            $paddedCounter = sprintf('%06d', $newNumber);

            return "{$paddedCounter}-{$customString}-{$currentDate}-{$currentTime}";
        });
    }
}

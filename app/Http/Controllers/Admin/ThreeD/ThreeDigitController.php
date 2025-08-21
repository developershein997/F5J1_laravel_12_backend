<?php

namespace App\Http\Controllers\Admin\ThreeD;

use App\Http\Controllers\Controller;
use App\Models\ThreeDigit\ThreeDBet;
use App\Models\ThreeDigit\ThreeDBetSlip;
use App\Models\ThreeDigit\ThreeDResult;
use App\Models\ThreeDigit\ThreeDLimit;
use App\Models\ThreeDigit\ThreeDCloseDigit;
use App\Models\ThreeDigit\ThreeDDrawSession;
use App\Services\ThreeDDrawService;
use App\Services\WalletService;
use App\Enums\DigitTransactionName;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use App\Models\User;

class ThreeDigitController extends Controller
{
    /**
     * 3D report index
     */
    public function index(Request $request)
    {
        $drawSession = $request->input('draw_session');
        $date = $request->input('date') ?? now()->toDateString();

        $user = auth()->user();

        if ($user->hasRole('Owner')) {
            $bets = ThreeDBet::where('draw_session', $drawSession)
                ->where('game_date', $date)
                ->with(['user', 'agent'])
                ->get();
        } elseif ($user->hasRole('Agent')) {
            $playerIds = $user->getAllDescendantPlayers()->pluck('id');
            $bets = ThreeDBet::whereIn('user_id', $playerIds)
                ->where('draw_session', $drawSession)
                ->where('game_date', $date)
                ->with('user')
                ->get();
        } else {
            // Player
            $bets = ThreeDBet::where('user_id', $user->id)
                ->where('draw_session', $drawSession)
                ->where('game_date', $date)
                ->get();
        }

        // Get available draw sessions for dropdown
        $availableDrawSessions = ThreeDDrawService::getDrawSessionsForYear();

        return view('admin.three_digit.report.index', compact('bets', 'availableDrawSessions'));
    }

    /**
     * 3D bet slip list
     */
    public function betSlipList(Request $request)
    {
        $drawSession = $request->input('draw_session');
        $date = $request->input('date', now()->toDateString());

        $query = ThreeDBetSlip::where('draw_session', $drawSession)
            ->whereDate('created_at', $date);

        // Optional: filter for agent/owner role
        if (auth()->user()->hasRole('Agent')) {
            // Only agent's players
            $playerIds = auth()->user()->getAllDescendantPlayers()->pluck('id');
            $query->whereIn('user_id', $playerIds);
        }

        $slips = $query->latest()->paginate(30);

        // Get available draw sessions for dropdown
        $availableDrawSessions = ThreeDDrawService::getDrawSessionsForYear();

        return view('admin.three_digit.report.index', compact('slips', 'availableDrawSessions'));
    }

    /**
     * 3D bet slip details
     */
    public function betSlipDetails($slip_id)
    {
        $user = auth()->user();

        // Fetch the slip (with user/agent relationships if needed)
        $slip = ThreeDBetSlip::with('user')->findOrFail($slip_id);

        // Only allow owner, or the agent whose player placed this slip, or the player himself
        if ($user->hasRole('Owner')) {
            // Owner can see all
        } elseif ($user->hasRole('Agent')) {
            // Agent: Only see their own players' slips
            $agentPlayerIds = $user->getAllDescendantPlayers()->pluck('id')->toArray();
            if (!in_array($slip->user_id, $agentPlayerIds)) {
                abort(403, 'Unauthorized');
            }
        } elseif ($user->id != $slip->user_id) {
            // Player: Only own slips
            abort(403, 'Unauthorized');
        }

        // Fetch all bets for this slip, with player info
        $bets = ThreeDBet::where('slip_id', $slip->id)
            ->with('user')
            ->orderBy('id')
            ->get();

        // Return Blade partial for AJAX load
        return view('admin.three_digit.report.details', compact('bets', 'slip'));
    }

    /**
     * 3D settings page
     */
    public function settings()
    {
        // Get all draw sessions for current year and convert to Collection
        $drawSessions = collect(ThreeDDrawService::getDrawSessionsWithStatus());
        
        // Get last 3D limit
        $threeDLimit = ThreeDLimit::orderBy('created_at', 'desc')->first();
        
        // Get last 3D result
        $threeDResult = ThreeDResult::orderBy('created_at', 'desc')->first();

        // Get all 3D close digits
        $threeDCloseDigits = ThreeDCloseDigit::orderBy('close_digit', 'asc')->get();

        // Get available draw sessions for dropdown
        $availableDrawSessions = ThreeDDrawService::getDrawSessionsForYear();

        // Calculate break group counts
        $breakGroupCounts = [];
        for ($i = 0; $i <= 27; $i++) {
            $breakGroupCounts[$i] = $this->getBreakGroupCount($i);
        }

        // Define quick patterns
        $quickPatterns = collect([
            ['name' => 'All Same', 'description' => '111, 222, 333...'],
            ['name' => 'Sequential', 'description' => '123, 234, 345...'],
            ['name' => 'Reverse', 'description' => '321, 432, 543...'],
            ['name' => 'Power Numbers', 'description' => '000, 111, 222, 333...'],
            ['name' => 'First 20', 'description' => '000 to 019'],
            ['name' => 'Last 20', 'description' => '980 to 999'],
        ]);

        return view('admin.three_digit.close_digit.index', compact(
            'drawSessions',
            'threeDLimit', 
            'threeDResult',
            'threeDCloseDigits',
            'availableDrawSessions',
            'breakGroupCounts',
            'quickPatterns'
        ));
    }

    /**
     * Calculate break group count for a given break group number
     */
    private function getBreakGroupCount($breakGroup)
    {
        // Count numbers from 000-999 that sum to $breakGroup
        $count = 0;
        for ($i = 0; $i <= 999; $i++) {
            $number = str_pad($i, 3, '0', STR_PAD_LEFT);
            if (array_sum(str_split($number)) == $breakGroup) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Store 3D limit
     */
    public function storeThreeDLimit(Request $request)
    {
        Log::info($request->all());
        $request->validate([
            'min_bet_amount' => 'required|numeric|min:0',
            'max_bet_amount' => 'required|numeric|min:0',
            'max_total_bet' => 'required|numeric|min:0',
            'payout_multiplier' => 'required|numeric|min:0',
        ]);

        // Deactivate all existing limits
        ThreeDLimit::where('is_active', true)->update(['is_active' => false]);

        $threeDLimit = ThreeDLimit::create([
            'min_bet_amount' => $request->min_bet_amount,
            'max_bet_amount' => $request->max_bet_amount,
            'max_total_bet' => $request->max_total_bet,
            'payout_multiplier' => $request->payout_multiplier,
            'is_active' => true,
        ]);

        Log::info($threeDLimit);

        return redirect()->route('admin.threed.settings')->with('success', '3D Limit settings updated successfully.');
    }

    /**
     * Store 3D result and process winners
     */
    public function storeThreeDResult(Request $request)
    {
        Log::info('storeThreeDResult called', ['request' => $request->all()]);
        
        try {
            $request->validate([
                'win_number' => 'required|string|size:3|regex:/^[0-9]{3}$/',
                'draw_session' => 'required|string',
                'result_date' => 'required|date',
                'result_time' => 'required|date_format:H:i',
            ]);

            $win_number = $request->win_number;
            $drawSession = $request->draw_session;

            Log::info('Validation passed', [
                'win_number' => $win_number,
                'draw_session' => $drawSession,
                'result_date' => $request->result_date,
                'result_time' => $request->result_time
            ]);

            DB::transaction(function () use ($request, $win_number, $drawSession) {
                // Check if result already exists for this draw session
                $existingResult = ThreeDResult::where('draw_session', $drawSession)->first();
                if ($existingResult) {
                    Log::warning('Result already exists for draw session', [
                        'draw_session' => $drawSession,
                        'existing_result' => $existingResult->win_number
                    ]);
                    throw new \Exception('Result already exists for this draw session.');
                }

                // Create 3D result
                $threeDResult = ThreeDResult::create([
                    'win_number' => $win_number,
                    'draw_session' => $drawSession,
                    'result_date' => $request->result_date,
                    'result_time' => $request->result_time,
                    'status' => 'declared',
                ]);
                Log::info('ThreeDResult created', ['threeDResult' => $threeDResult]);

                // Find all bets for this draw session
                $allBets = ThreeDBet::where('draw_session', $drawSession)->get();
                Log::info('Fetched bets', [
                    'count' => $allBets->count(),
                    'draw_session' => $drawSession,
                    'bet_ids' => $allBets->pluck('id')->toArray()
                ]);

                $totalWinners = 0;
                $totalPrizeAmount = 0;

                // Process each bet
                foreach ($allBets as $bet) {
                    $totalPrize = 0;
                    $prizeDetails = [];
                    $isPermutationWinner = false;
                    
                    Log::info('Processing bet', [
                        'bet_id' => $bet->id,
                        'bet_number' => $bet->bet_number,
                        'bet_amount' => $bet->bet_amount,
                        'win_number' => $win_number
                    ]);
                    
                    // Check for exact match (First Prize: 500x)
                    $isExactWinner = $bet->bet_number == $win_number;
                    if ($isExactWinner) {
                        $firstPrize = $bet->bet_amount * 500;
                        $totalPrize += $firstPrize;
                        $prizeDetails[] = "First Prize: {$firstPrize} (500x)";
                        $totalWinners++;
                        $totalPrizeAmount += $firstPrize;
                        Log::info('Exact match found', [
                            'bet_id' => $bet->id,
                            'bet_number' => $bet->bet_number,
                            'win_number' => $win_number,
                            'first_prize' => $firstPrize
                        ]);
                    } else {
                        // Check for permutation match (Permutation Prize: 100x)
                        $permutations = $bet->generatePermutations();
                        $isPermutationWinner = in_array($win_number, $permutations);
                        
                        Log::info('Checking permutations', [
                            'bet_id' => $bet->id,
                            'bet_number' => $bet->bet_number,
                            'permutations' => $permutations,
                            'win_number' => $win_number,
                            'is_permutation_winner' => $isPermutationWinner
                        ]);
                        
                        if ($isPermutationWinner) {
                            $permutationPrize = $bet->bet_amount * 100; // 100x for permutation match
                            $totalPrize += $permutationPrize;
                            $prizeDetails[] = "Permutation Prize: {$permutationPrize} (100x for permutation match)";
                            $totalWinners++;
                            $totalPrizeAmount += $permutationPrize;
                            Log::info('Permutation match found', [
                                'bet_id' => $bet->id,
                                'bet_number' => $bet->bet_number,
                                'win_number' => $win_number,
                                'permutation_prize' => $permutationPrize
                            ]);
                        }
                    }

                    // Process prize if any winnings
                    if ($totalPrize > 0) {
                        // Update player wallet using WalletService
                        $player = User::find($bet->user_id);
                        if ($player) {
                            try {
                                app(WalletService::class)->deposit($player, $totalPrize, DigitTransactionName::ThreeDigitBetWin, [
                                    'bet_id' => $bet->id,
                                    'win_number' => $win_number,
                                    'draw_session' => $drawSession,
                                    'result_date' => $request->result_date,
                                    'bet_amount' => $bet->bet_amount,
                                    'prize_amount' => $totalPrize,
                                    'prize_details' => implode(', ', $prizeDetails),
                                    'slip_id' => $bet->slip_id,
                                    'is_exact_winner' => $isExactWinner,
                                    'is_permutation_winner' => $isPermutationWinner
                                ]);
                                Log::info('Prize deposited to player wallet', [
                                    'user_id' => $player->id, 
                                    'total_prize' => $totalPrize,
                                    'prize_details' => $prizeDetails,
                                    'new_balance' => $player->balanceFloat
                                ]);
                            } catch (\Exception $e) {
                                Log::error('Failed to deposit prize to player wallet', [
                                    'user_id' => $player->id,
                                    'total_prize' => $totalPrize,
                                    'error' => $e->getMessage()
                                ]);
                                throw $e;
                            }
                        }

                        // Update bet as win
                        $bet->win_lose = true;
                        $bet->potential_payout = $totalPrize;
                        $bet->prize_sent = true;
                        Log::info('Bet marked as win', [
                            'bet_id' => $bet->id, 
                            'total_prize' => $totalPrize,
                            'prize_details' => $prizeDetails
                        ]);
                    } else {
                        // Update bet as lose
                        $bet->win_lose = false;
                        $bet->potential_payout = 0;
                        $bet->prize_sent = false;
                        Log::info('Bet marked as lose', ['bet_id' => $bet->id]);
                    }

                    // Update all common fields
                    $bet->bet_status = true; // settled
                    $bet->bet_result = $win_number;
                    $bet->save();
                }

                // Update all slips for this draw session to completed
                $updated = ThreeDBetSlip::where('draw_session', $drawSession)
                    ->update(['status' => 'completed']);
                Log::info('Updated slips to completed', ['updated_count' => $updated]);

                // Update result status to completed
                $threeDResult->update(['status' => 'completed']);

                Log::info('Result processing completed', [
                    'total_bets_processed' => $allBets->count(),
                    'total_winners' => $totalWinners,
                    'total_prize_amount' => $totalPrizeAmount,
                    'win_number' => $win_number,
                    'draw_session' => $drawSession
                ]);
            });

            return redirect()->route('admin.threed.settings')->with('success', '3D Result added and winners paid with new prize structure.');
            
        } catch (\Exception $e) {
            Log::error('Error in storeThreeDResult', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'request' => $request->all()
            ]);
            
            return redirect()->route('admin.threed.settings')->with('error', 'Error processing 3D result: ' . $e->getMessage());
        }
    }

    /**
     * Daily ledger for 3D
     */
    public function dailyLedger(Request $request)
    {
        $user = Auth::user();
        $drawSession = $request->input('draw_session');
        $date = $request->input('date') ?? now()->format('Y-m-d');

        // If no draw session is selected, default to current draw session
        if (!$drawSession || $drawSession === 'all') {
            $currentDate = now();
            $currentYear = $currentDate->year;
            $drawSessions = ThreeDDrawService::getDrawSessionsForYear($currentYear);
            
            // Find the current or next draw session
            $drawSession = null;
            foreach ($drawSessions as $session) {
                $sessionDate = \Carbon\Carbon::parse($session);
                if ($sessionDate->gte($currentDate->startOfDay())) {
                    $drawSession = $session;
                    break;
                }
            }
            
            // If no current/next session found, use the last session
            if (!$drawSession) {
                $drawSession = end($drawSessions);
            }
        }

        // Query for the specific draw session
        $query = DB::table('three_d_bets')
            ->select('bet_number', DB::raw('SUM(bet_amount) as total_amount'))
            ->where('draw_session', $drawSession)
            ->where('game_date', $date);

        // Restrict by agent if not owner
        if ($user->type == \App\Enums\UserType::Agent || $user->type == \App\Enums\UserType::SubAgent) {
            $query->where('agent_id', $user->id);
        }

        $bets = $query->groupBy('bet_number')->get();

        // Generate all numbers 000–999 with bet amounts
        $allNumbers = collect(range(0, 999))->map(function ($n) {
            return str_pad($n, 3, '0', STR_PAD_LEFT);
        });

        $result = $allNumbers->mapWithKeys(function ($num) use ($bets) {
            $amount = $bets->firstWhere('bet_number', $num)?->total_amount ?? 0;
            return [$num => (float) $amount];
        });

        // Get available draw sessions for dropdown
        $availableDrawSessions = ThreeDDrawService::getDrawSessionsForYear();

        return view('admin.three_digit.ledger.index', compact('result', 'drawSession', 'availableDrawSessions', 'date'));
    }

    /**
     * Daily winners for 3D
     */
    public function dailyWinners(Request $request)
    {
        $user = Auth::user();
        $drawSession = $request->input('draw_session');
        $date = $request->input('date') ?? now()->format('Y-m-d');
        
        // If no specific draw session is selected, show all sessions with results
        if (!$drawSession || $drawSession === 'all') {
            $drawSession = null;
        }

        if ($drawSession) {
            // Return only one draw session
            $result = DB::table('three_d_results')
                ->where('draw_session', $drawSession)
                ->first();

            if (!$result || !$result->win_number) {
                return response()->json(['message' => 'Winning result not found for this draw session'], 404);
            }

            $winDigit = $result->win_number;

            // Get all winning bets (both exact and permutation matches)
            $query = DB::table('three_d_bets')
                ->select('bet_number', DB::raw('SUM(bet_amount) as total_bet'), DB::raw('SUM(potential_payout) as win_amount'))
                ->where('draw_session', $drawSession)
                ->where('win_lose', true)
                ->where('prize_sent', true);

            // Restrict by agent
            if (in_array($user->type, [\App\Enums\UserType::Agent, \App\Enums\UserType::SubAgent])) {
                $query->where('agent_id', $user->id);
            }

            $winners = $query->groupBy('bet_number')->get();

            // Get available draw sessions for dropdown
            $availableDrawSessions = ThreeDDrawService::getDrawSessionsForYear();

            return view('admin.three_digit.winner.index', [
                'date' => $date,
                'drawSession' => $drawSession,
                'results' => $result,
                'winners' => $winners,
                'availableDrawSessions' => $availableDrawSessions,
            ]);
        }

        // Return all draw sessions
        $drawSessions = collect(ThreeDDrawService::getDrawSessionsForYear());
        $result = [];

        foreach ($drawSessions as $session) {
            $res = DB::table('three_d_results')
                ->where('draw_session', $session)
                ->first();

            if ($res && $res->win_number) {
                // Get all winning bets (both exact and permutation matches)
                $query = DB::table('three_d_bets')
                    ->select('bet_number', DB::raw('SUM(bet_amount) as total_bet'), DB::raw('SUM(potential_payout) as win_amount'))
                    ->where('draw_session', $session)
                    ->where('win_lose', true)
                    ->where('prize_sent', true);

                // Restrict by agent if not owner
                if (in_array($user->type, [\App\Enums\UserType::Agent, \App\Enums\UserType::SubAgent])) {
                    $query->where('agent_id', $user->id);
                }

                $winners = $query->groupBy('bet_number')->get();

                $result[$session] = [
                    'win_digit' => $res->win_number,
                    'winners' => $winners,
                ];
            } else {
                $result[$session] = ['message' => 'No result found'];
            }
        }

        // Get available draw sessions for dropdown
        $availableDrawSessions = ThreeDDrawService::getDrawSessionsForYear();

        return view('admin.three_digit.winner.index', [
            'date' => $date,
            'drawSession' => $drawSession ?? null,
            'result' => $result ?? null,
            'availableDrawSessions' => $availableDrawSessions,
        ]);
    }

    /**
     * Get break groups for 3D
     */
    public function getBreakGroups()
    {
        $breakGroups = [];
        
        for ($sum = 0; $sum <= 27; $sum++) {
            $numbers = [];
            for ($i = 0; $i <= 999; $i++) {
                $num = str_pad($i, 3, '0', STR_PAD_LEFT);
                $digitSum = array_sum(str_split($num));
                if ($digitSum === $sum) {
                    $numbers[] = $num;
                }
            }
            $breakGroups[] = [
                'break_number' => $sum,
                'name' => "Break {$sum}",
                'numbers' => $numbers,
                'count' => count($numbers)
            ];
        }

        return response()->json([
            'success' => true,
            'data' => [
                'break_groups' => $breakGroups
            ]
        ]);
    }

    /**
     * Get quick selection patterns for 3D
     */
    public function getQuickPatterns()
    {
        $patterns = [
            [
                'id' => 'single_double',
                'name' => 'Single/Double Numbers',
                'description' => 'Numbers with single and double digits',
                'numbers' => ['111', '222', '333', '444', '555', '666', '777', '888', '999']
            ],
            [
                'id' => 'front_back',
                'name' => 'Front/Back Numbers',
                'description' => 'Front and back number patterns',
                'numbers' => ['123', '321', '456', '654', '789', '987', '012', '210', '345', '543']
            ],
            [
                'id' => 'power_numbers',
                'name' => 'Power Numbers',
                'description' => 'Special power number combinations',
                'numbers' => ['000', '111', '222', '333', '444', '555', '666', '777', '888', '999']
            ],
            [
                'id' => 'first_20',
                'name' => 'First 20 Numbers',
                'description' => 'Numbers from 000 to 019',
                'numbers' => array_map(function($i) { return str_pad($i, 3, '0', STR_PAD_LEFT); }, range(0, 19))
            ]
        ];

        return response()->json([
            'success' => true,
            'data' => [
                'patterns' => $patterns
            ]
        ]);
    }

    /**
     * Toggle 3D close digit status
     */
    public function toggleThreeDCloseDigit(Request $request)
    {
        $request->validate([
            'close_digit' => 'required|string|size:3|regex:/^[0-9]{3}$/',
        ]);

        $closeDigit = ThreeDCloseDigit::where('close_digit', $request->close_digit)->first();

        if (!$closeDigit) {
            return response()->json([
                'success' => false,
                'message' => 'Close digit not found'
            ], 404);
        }

        // Toggle status
        $closeDigit->status = !$closeDigit->status;
        $closeDigit->save();

        return response()->json([
            'success' => true,
            'message' => '3D close digit status updated successfully',
            'data' => [
                'close_digit' => $closeDigit->close_digit,
                'status' => $closeDigit->status,
                'status_text' => $closeDigit->status ? 'Open' : 'Closed'
            ]
        ]);
    }

    /**
     * Get 3D close digits status
     */
    public function getThreeDCloseDigits()
    {
        $closeDigits = ThreeDCloseDigit::orderBy('close_digit', 'asc')->get();

        return response()->json([
            'success' => true,
            'data' => [
                'close_digits' => $closeDigits->map(function($digit) {
                    return [
                        'close_digit' => $digit->close_digit,
                        'status' => $digit->status,
                        'status_text' => $digit->status ? 'Open' : 'Closed'
                    ];
                })
            ]
        ]);
    }

    /**
     * Toggle draw session status (open/close)
     */
    public function toggleDrawSession(Request $request)
    {
        $request->validate([
            'draw_session' => 'required|string',
            'is_open' => 'required'
        ]);

        try {
            // Convert is_open to boolean properly
            $isOpen = filter_var($request->is_open, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
            
            if ($isOpen === null) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid is_open value. Must be true or false.'
                ], 422);
            }

            $drawSession = ThreeDDrawSession::updateOrCreate(
                ['draw_session' => $request->draw_session],
                [
                    'is_open' => $isOpen,
                    'notes' => $request->notes ?? null
                ]
            );

            return response()->json([
                'success' => true,
                'message' => 'Draw session status updated successfully',
                'data' => [
                    'draw_session' => $drawSession->draw_session,
                    'is_open' => $drawSession->is_open
                ]
            ]);
        } catch (\Exception $e) {
            Log::error('Error toggling draw session: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'message' => 'Failed to update draw session status'
            ], 500);
        }
    }

    /**
     * Manually trigger draw session transition
     */
    public function triggerSessionTransition(Request $request)
    {
        try {
            $result = ThreeDDrawService::autoTransitionDrawSessions();
            
            $message = 'Draw session transition completed successfully.';
            $details = [];
            
            if ($result['current_session']) {
                $details[] = "Current session: {$result['current_session']}";
                if ($result['current_closed']) {
                    $details[] = "✓ Current session auto-closed";
                }
            }
            
            if ($result['next_session']) {
                $details[] = "Next session: {$result['next_session']}";
                if ($result['next_opened']) {
                    $details[] = "✓ Next session auto-opened";
                }
            }
            
            return response()->json([
                'success' => true,
                'message' => $message,
                'details' => $details,
                'data' => $result
            ]);
            
        } catch (\Exception $e) {
            Log::error('Error triggering session transition: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'message' => 'Failed to trigger session transition: ' . $e->getMessage()
            ], 500);
        }
    }
}

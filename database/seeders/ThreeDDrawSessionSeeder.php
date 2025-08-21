<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use App\Services\ThreeDDrawService;
use Carbon\Carbon;

class ThreeDDrawSessionSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Clear existing data
        DB::table('three_d_draw_sessions')->delete();

        // Get all draw sessions for current year
        $drawSessions = ThreeDDrawService::getDrawSessionsForYear();
        $currentDate = Carbon::now();

        // Insert all draw sessions with appropriate default status
        foreach ($drawSessions as $session) {
            $sessionDate = Carbon::parse($session);
            
            // Determine if this is the current session
            $isCurrentSession = $sessionDate->eq($currentDate->startOfDay());
            
            // Default: only current session is open, others are closed
            $defaultIsOpen = $isCurrentSession;

            DB::table('three_d_draw_sessions')->insert([
                'draw_session' => $session,
                'is_open' => $defaultIsOpen,
                'notes' => $isCurrentSession ? 'Current draw session - open by default' : 'Closed by default',
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }
    }
}

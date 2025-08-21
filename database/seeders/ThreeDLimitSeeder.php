<?php

namespace Database\Seeders;

use App\Models\ThreeDigit\ThreeDLimit;
use Illuminate\Database\Seeder;

class ThreeDLimitSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Create default 3D limit settings
        ThreeDLimit::create([
            'min_bet_amount' => 1.00,
            'max_bet_amount' => 10000.00,
            'max_total_bet' => 100000.00,
            'payout_multiplier' => 800.00, // 800x for 3D
            'is_active' => true,
            'description' => 'Default 3D betting limits - 800x payout multiplier',
        ]);

        $this->command->info('3D betting limits seeded successfully!');
    }
}

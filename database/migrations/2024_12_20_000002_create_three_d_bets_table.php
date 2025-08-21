<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('three_d_bets', function (Blueprint $table) {
            $table->id();

            // Foreign key to users table
            $table->foreignId('user_id')->constrained('users')->onDelete('cascade');
            $table->string('member_name')->nullable();
            
            // Foreign key to agents table
            $table->foreignId('agent_id')->nullable()->constrained('users')->onDelete('set null');

            // 3-digit bet number (000-999)
            $table->string('bet_number', 3); // The 3-digit number (e.g., '123', '999')
            $table->decimal('bet_amount', 10, 2);
            
            // For permutation bets (if user bets on all arrangements)
            $table->boolean('is_permutation')->default(false);
            $table->decimal('permutation_amount', 10, 2)->nullable();
            
            // Break group (sum of digits 0-27)
            $table->unsignedTinyInteger('break_group')->nullable();
            
            $table->string('draw_session'); // e.g., '2024-01-16', '2024-02-01', etc.
            $table->boolean('win_lose')->default(false);
            $table->decimal('potential_payout', 10, 2)->default(0);
            $table->boolean('bet_status')->default(false)->comment('false: pending, true: settled');
            $table->string('bet_result')->nullable()->comment('Stores winning number or outcome message');
            $table->boolean('prize_sent')->default(false);
            
            // Game date and time
            $table->date('game_date');
            $table->time('game_time')->nullable();
            
            // Reference to slip
            $table->unsignedBigInteger('slip_id');
            
            // Balance tracking
            $table->decimal('before_balance', 10, 2)->nullable();
            $table->decimal('after_balance', 10, 2)->nullable();

            $table->timestamps();

            $table->foreign('slip_id')->references('id')->on('three_d_bet_slips')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('three_d_bets');
    }
};

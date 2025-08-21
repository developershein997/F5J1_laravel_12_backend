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
        Schema::create('three_d_results', function (Blueprint $table) {
            $table->id();
            $table->string('win_number', 3); // e.g., '123', '999'
            $table->string('draw_session')->unique(); // e.g., '2024-01-16', '2024-02-01', etc.
            $table->date('result_date'); // The day this result applies to
            $table->time('result_time')->nullable(); // Time when result declared
            $table->unsignedTinyInteger('break_group'); // Sum of digits (0-27)
            $table->enum('status', ['pending', 'declared', 'completed'])->default('pending');
            $table->text('notes')->nullable();
            $table->timestamps();

            // Prevent duplicate result for same draw session
            $table->unique(['draw_session'], 'unique_draw_session');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('three_d_results');
    }
};

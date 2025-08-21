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
        Schema::create('three_d_close_digits', function (Blueprint $table) {
            $table->id();
            $table->string('close_digit', 3)->unique(); // 3-digit number (000-999)
            $table->boolean('status')->default(true); // true: open, false: closed
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('three_d_close_digits');
    }
};

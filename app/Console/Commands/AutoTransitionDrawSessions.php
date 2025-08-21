<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Services\ThreeDDrawService;

class AutoTransitionDrawSessions extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'threed:transition-sessions {--force : Force transition regardless of time}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Automatically transition 3D draw sessions when current session ends';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('Starting automatic draw session transition...');
        
        try {
            $result = ThreeDDrawService::autoTransitionDrawSessions();
            
            $this->info('Transition completed successfully!');
            
            if ($result['current_session']) {
                $this->line("Current session: {$result['current_session']}");
                if ($result['current_closed']) {
                    $this->warn("✓ Current session auto-closed");
                }
            }
            
            if ($result['next_session']) {
                $this->line("Next session: {$result['next_session']}");
                if ($result['next_opened']) {
                    $this->info("✓ Next session auto-opened");
                }
            }
            
            if (!$result['current_session'] && !$result['next_session']) {
                $this->warn("No draw sessions found for today or upcoming dates.");
            }
            
        } catch (\Exception $e) {
            $this->error("Error during transition: " . $e->getMessage());
            return 1;
        }
        
        return 0;
    }
}

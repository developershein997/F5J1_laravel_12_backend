<?php

namespace App\Services;

use Carbon\Carbon;

class ThreeDDrawService
{
    /**
     * Get all draw sessions for a given year
     */
    public static function getDrawSessionsForYear($year = null)
    {
        if (!$year) {
            $year = Carbon::now()->year;
        }

        $drawSessions = [];
        
        // January: 16th only
        $drawSessions[] = Carbon::create($year, 1, 16)->format('Y-m-d');
        
        // February to December: 1st and 16th
        for ($month = 2; $month <= 12; $month++) {
            $drawSessions[] = Carbon::create($year, $month, 1)->format('Y-m-d');
            $drawSessions[] = Carbon::create($year, $month, 16)->format('Y-m-d');
        }
        
        // December: additional 30th
        $drawSessions[] = Carbon::create($year, 12, 30)->format('Y-m-d'); // December 30th

        return $drawSessions;
    }

    /**
     * Get the next draw session
     */
    public static function getNextDrawSession()
    {
        $currentDate = Carbon::now();
        $currentYear = $currentDate->year;
        $nextYear = $currentYear + 1;
        
        // Get all draw sessions for current and next year
        $currentYearSessions = self::getDrawSessionsForYear($currentYear);
        $nextYearSessions = self::getDrawSessionsForYear($nextYear);
        
        $allSessions = array_merge($currentYearSessions, $nextYearSessions);
        
        // Find the next session after today
        foreach ($allSessions as $session) {
            $sessionDate = Carbon::parse($session);
            if ($sessionDate->gt($currentDate)) {
                return $session;
            }
        }
        
        return null;
    }

    /**
     * Get the current draw session (if today is a draw day)
     */
    public static function getCurrentDrawSession()
    {
        $today = Carbon::now()->format('Y-m-d');
        $currentYear = Carbon::now()->year;
        $drawSessions = self::getDrawSessionsForYear($currentYear);
        
        if (in_array($today, $drawSessions)) {
            return $today;
        }
        
        return null;
    }

    /**
     * Get the current draw session with status
     */
    public static function getCurrentDrawSessionWithStatus()
    {
        $currentSession = self::getCurrentDrawSession();
        
        if (!$currentSession) {
            return null;
        }
        
        $sessionsWithStatus = self::getDrawSessionsWithStatus();
        
        return collect($sessionsWithStatus)->firstWhere('date', $currentSession);
    }

    /**
     * Automatically transition draw sessions when current session ends
     * This should be called periodically (e.g., via cron job)
     */
    public static function autoTransitionDrawSessions()
    {
        $currentDate = Carbon::now();
        $currentYear = $currentDate->year;
        $nextYear = $currentYear + 1;
        
        // Get all draw sessions for current and next year
        $currentYearSessions = self::getDrawSessionsForYear($currentYear);
        $nextYearSessions = self::getDrawSessionsForYear($nextYear);
        $allSessions = array_merge($currentYearSessions, $nextYearSessions);
        
        // Find the current session (if any)
        $currentSession = null;
        $nextSession = null;
        
        foreach ($allSessions as $session) {
            $sessionDate = Carbon::parse($session);
            
            // Check if this is the current session (today)
            if ($sessionDate->eq($currentDate->startOfDay())) {
                $currentSession = $session;
            }
            
            // Find the next session after today
            if ($sessionDate->gt($currentDate) && !$nextSession) {
                $nextSession = $session;
            }
        }
        
        $transitions = [];
        
        // Close current session if it's past 2:30 PM (draw time)
        if ($currentSession) {
            $currentSessionRecord = \App\Models\ThreeDigit\ThreeDDrawSession::where('draw_session', $currentSession)->first();
            
            if ($currentDate->hour >= 14 && $currentDate->minute >= 30) {
                if ($currentSessionRecord && $currentSessionRecord->is_open) {
                    $currentSessionRecord->update([
                        'is_open' => false,
                        'notes' => 'Automatically closed after draw time'
                    ]);
                    
                    \Log::info("Auto-closed current draw session: {$currentSession}");
                    $transitions[] = "Closed current session: {$currentSession}";
                }
            }
        }
        
        // Close ALL open sessions except the next one
        $allOpenSessions = \App\Models\ThreeDigit\ThreeDDrawSession::where('is_open', true)->get();
        
        foreach ($allOpenSessions as $openSession) {
            // Don't close the next session if it's already open
            if ($nextSession && $openSession->draw_session === $nextSession) {
                continue;
            }
            
            // Close all other open sessions
            $openSession->update([
                'is_open' => false,
                'notes' => 'Automatically closed to ensure only one session is open'
            ]);
            
            \Log::info("Auto-closed draw session: {$openSession->draw_session}");
            $transitions[] = "Closed session: {$openSession->draw_session}";
        }
        
        // Open the next session if it exists and isn't already open
        if ($nextSession) {
            $nextSessionRecord = \App\Models\ThreeDigit\ThreeDDrawSession::where('draw_session', $nextSession)->first();
            
            if ($nextSessionRecord && !$nextSessionRecord->is_open) {
                $nextSessionRecord->update([
                    'is_open' => true,
                    'notes' => 'Automatically opened as next draw session'
                ]);
                
                \Log::info("Auto-opened next draw session: {$nextSession}");
                $transitions[] = "Opened next session: {$nextSession}";
            }
        }
        
        return [
            'current_session' => $currentSession,
            'next_session' => $nextSession,
            'current_closed' => $currentSession ? ($currentDate->hour >= 14 && $currentDate->minute >= 30) : false,
            'next_opened' => $nextSession ? true : false,
            'transitions' => $transitions
        ];
    }

    /**
     * Get the last draw session
     */
    public static function getLastDrawSession()
    {
        $currentDate = Carbon::now();
        $currentYear = $currentDate->year;
        $previousYear = $currentYear - 1;
        
        // Get all draw sessions for previous and current year
        $previousYearSessions = self::getDrawSessionsForYear($previousYear);
        $currentYearSessions = self::getDrawSessionsForYear($currentYear);
        
        $allSessions = array_merge($previousYearSessions, $currentYearSessions);
        
        // Find the last session before today
        $lastSession = null;
        foreach ($allSessions as $session) {
            $sessionDate = Carbon::parse($session);
            if ($sessionDate->lt($currentDate)) {
                $lastSession = $session;
            } else {
                break;
            }
        }
        
        return $lastSession;
    }

    /**
     * Check if betting is open for a specific draw session
     */
    public static function isBettingOpen($drawSession)
    {
        $drawDate = Carbon::parse($drawSession);
        $currentDate = Carbon::now();
        
        // Betting closes 2 hours before draw time (assuming draw time is 2:30 PM)
        $closingTime = $drawDate->copy()->setTime(14, 30)->subHours(2);
        
        return $currentDate->lt($closingTime);
    }

    /**
     * Get draw sessions for a specific month
     */
    public static function getDrawSessionsForMonth($year, $month)
    {
        $allSessions = self::getDrawSessionsForYear($year);
        $monthSessions = [];
        
        foreach ($allSessions as $session) {
            $sessionDate = Carbon::parse($session);
            if ($sessionDate->month == $month) {
                $monthSessions[] = $session;
            }
        }
        
        return $monthSessions;
    }

    /**
     * Get draw sessions with status (past, current, future) and open/close status
     */
    public static function getDrawSessionsWithStatus($year = null)
    {
        if (!$year) {
            $year = Carbon::now()->year;
        }

        $drawSessions = self::getDrawSessionsForYear($year);
        $currentDate = Carbon::now();
        $sessionsWithStatus = [];

        // Get draw session statuses from database
        $sessionStatuses = \App\Models\ThreeDigit\ThreeDDrawSession::pluck('is_open', 'draw_session')->toArray();

        foreach ($drawSessions as $session) {
            $sessionDate = Carbon::parse($session);
            
            if ($sessionDate->lt($currentDate)) {
                $status = 'past';
            } elseif ($sessionDate->eq($currentDate->startOfDay())) {
                $status = 'current';
            } else {
                $status = 'future';
            }

            // Default status: only current session is open, others are closed
            $defaultIsOpen = ($status === 'current');
            
            // Use database value if exists, otherwise use default
            $isOpen = isset($sessionStatuses[$session]) ? $sessionStatuses[$session] : $defaultIsOpen;

            $sessionsWithStatus[] = [
                'date' => $session,
                'status' => $status,
                'is_betting_open' => self::isBettingOpen($session),
                'is_open' => $isOpen
            ];
        }

        return $sessionsWithStatus;
    }
}

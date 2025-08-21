@extends('layouts.master')
@section('content')
<section class="content-header">
    <div class="container-fluid">
        <div class="row mb-2 align-items-center">
            <div class="col-sm-6">
                <h1>3D Bet Daily Ledger</h1>
            </div>
            <div class="col-sm-6">
                <form class="form-inline float-sm-right" method="GET">
                    <input type="date" name="date" class="form-control mr-2" value="{{ request('date', now()->toDateString()) }}">
                    <select name="draw_session" class="form-control mr-2" required>
                        <option value="">Select Draw Session</option>
                        @foreach($availableDrawSessions as $session)
                            <option value="{{ $session }}" {{ request('draw_session') == $session ? 'selected' : '' }}>
                                {{ $session }}
                            </option>
                        @endforeach
                    </select>
                    <button type="submit" class="btn btn-primary">Filter</button>
                </form>
            </div>
        </div>
    </div>
</section>

<section class="content">
    <div class="container-fluid">
        <!-- Single Draw Session View -->
        <div class="card shadow">
            <div class="card-header">
                <h3 class="card-title">
                    <i class="fas fa-calendar-alt text-primary"></i>
                    3D Ledger - {{ $drawSession }} ({{ $date }})
                </h3>
                <div class="card-tools">
                    <span class="badge badge-info">Total Numbers: {{ count($result) }}</span>
                    <span class="badge badge-success">Active Numbers: {{ $result->filter(function($amount) { return $amount > 0; })->count() }}</span>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead class="thead-dark">
                            <tr>
                                <th width="15%">Number</th>
                                <th width="25%">Total Bet Amount</th>
                                <th width="20%">Break Group</th>
                                <th width="15%">Status</th>
                                <th width="25%">Permutations</th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach($result as $number => $amount)
                                @php
                                    $breakGroup = array_sum(str_split(str_pad($number, 3, '0', STR_PAD_LEFT)));
                                    $permutations = [];
                                    if ($amount > 0) {
                                        $digits = str_split(str_pad($number, 3, '0', STR_PAD_LEFT));
                                        $permutations = array_unique(array_map(function($p) {
                                            return implode('', $p);
                                        }, getPermutations($digits)));
                                    }
                                @endphp
                                <tr class="{{ $amount > 0 ? 'table-success' : '' }}">
                                    <td>
                                        <strong class="text-primary">{{ str_pad($number, 3, '0', STR_PAD_LEFT) }}</strong>
                                    </td>
                                    <td class="{{ $amount > 0 ? 'text-success font-weight-bold' : 'text-muted' }}">
                                        {{ number_format($amount, 2) }}
                                    </td>
                                    <td>
                                        <span class="badge badge-warning">Break {{ $breakGroup }}</span>
                                    </td>
                                    <td>
                                        @if($amount > 0)
                                            <span class="badge badge-success">
                                                <i class="fas fa-check"></i> Active
                                            </span>
                                        @else
                                            <span class="badge badge-secondary">
                                                <i class="fas fa-times"></i> No Bets
                                            </span>
                                        @endif
                                    </td>
                                    <td>
                                        @if($amount > 0 && count($permutations) > 1)
                                            <small class="text-info">
                                                {{ implode(', ', $permutations) }}
                                            </small>
                                        @else
                                            <small class="text-muted">-</small>
                                        @endif
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</section>

@php
    function getPermutations($arr) {
        if (count($arr) <= 1) {
            return [$arr];
        }
        
        $permutations = [];
        for ($i = 0; $i < count($arr); $i++) {
            $current = $arr[$i];
            $remaining = array_merge(array_slice($arr, 0, $i), array_slice($arr, $i + 1));
            
            foreach (getPermutations($remaining) as $perm) {
                $permutations[] = array_merge([$current], $perm);
            }
        }
        
        return $permutations;
    }
@endphp

<script>
$(document).ready(function() {
    // Initialize DataTable for better UX
    $('.table').DataTable({
        "pageLength": 25,
        "order": [[0, "asc"]],
        "responsive": true
    });
});
</script>
@endsection

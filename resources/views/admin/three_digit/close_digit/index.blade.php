@extends('layouts.master')
@section('style')
<style>
    .digits-flex-container {
    display: flex;
    flex-direction: row;
    justify-content: center;
    gap: 20px;
    flex-wrap: wrap;
    margin-bottom: 20px;
    scrollbar-width: thin;
    scrollbar-color: #ccc #f8f9fa;
}
.digits-flex-container::-webkit-scrollbar {
    height: 8px;
}
.digits-flex-container::-webkit-scrollbar-thumb {
    background: #ccc;
    border-radius: 4px;
}
.digit-item {
    min-width: 80px;
    min-height: 100px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    margin-bottom: 10px;
    font-size: 1.5rem;
    font-weight: bold;
    transition: background 0.2s, color 0.2s, border 0.2s;
    position: relative;
}
.digit-number {
    font-size: 2rem;
    margin-bottom: 10px;
}
.digit-toggle {
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
}
.digit-status {
    font-size: 1rem;
    font-weight: 600;
    text-align: center;
}
.horizontal-bar {
    display: flex;
    flex-direction: row;
    align-items: center;
    border: 1px solid #fff;
    background: #222;
    width: fit-content;
    margin: 0 auto 4px auto;
    overflow-x: auto;
    max-width: 100%;
}
.digit-box {
    border: 1px solid #fff;
    color: #fff;
    background: #222;
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.2rem;
    font-weight: bold;
    cursor: pointer;
    transition: background 0.2s, color 0.2s;
}
.digit-box.active {
    background: #28a745;
    color: #fff;
    border-color: #28a745;
}
.horizontal-bar-group {
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 8px;
}
.choose-digit-section {
    padding: 20px 0;
}
.choose-digit-title {
    font-size: 1.2rem;
    font-weight: 600;
    margin-bottom: 12px;
    color: #333;
}
.horizontal-bar-group {
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 12px;
}
.horizontal-bar-modern {
    display: flex;
    flex-direction: row;
    gap: 10px;
    justify-content: center;
    margin-bottom: 2px;
}
.digit-box-modern {
    background: #23272f;
    border-radius: 10px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    border: 2px solid #444;
    color: #fff;
    width: 100px;
    height: 100px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
    font-weight: 800;
    cursor: pointer;
    transition: background 0.2s, border 0.2s, color 0.2s, box-shadow 0.2s;
    position: relative;
    user-select: none;
}
.digit-box-modern:hover {
    background: #2d323c;
    border-color: #007bff;
    color: #fff;
    box-shadow: 0 4px 16px rgba(0,123,255,0.10);
}
.digit-box-modern.active {
    background:rgb(129, 29, 142);
    border-color: #28a745;
    border-width: 3px;
    color: #fff;
}
.digit-box-modern.inactive {
    background: #222 !important;
    border-color: #222 !important;
    color: #fff;
}
.digit-label {
    font-size: 1.2rem;
    letter-spacing: 1px;
}
.toggle-indicator {
    margin-top: 4px;
    width: 30px;
    height: 15px;
    background: #444;
    border-radius: 6px;
    position: relative;
    transition: background 0.2s;
    display: flex;
    align-items: center;
}
.digit-box-modern.active .toggle-indicator {
    background: #fff;
}
.toggle-dot {
    width: 12px;
    height: 12px;
    background: #bbb;
    border-radius: 50%;
    transition: background 0.2s, transform 0.2s;
    box-shadow: 0 1px 3px rgba(0,0,0,0.10);
}
.digit-box-modern.active .toggle-dot {
    background: #28a745;
    transform: translateX(10px);
}
.digit-item.inactive {
    background: #222 !important;
    border-color: #222 !important;
    color: #fff;
}
.digit-item.active {
    background: #28a745;
    color: #fff;
    border-color: #28a745;
}

.horizontal-bar-group {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    justify-content: center;
    max-width: 800px;
    margin: 0 auto;
}
.horizontal-bar-modern {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.digit-box-modern {
    background-color:rgb(22, 9, 31);
    border: 2px solidrgb(90, 8, 8);
    border-radius: 10px;
    color: #fff;
    padding: 15px 20px;
    text-align: center;
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-width: 150px;
    height: 120px;
    position: relative;
    overflow: hidden;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}
.digit-box-modern:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 12px rgba(0, 0, 0, 0.3);
}
.digit-box-modern.active {
    background-color:rgb(10, 111, 61);
    border-color:rgb(194, 23, 151);
}

/* Draw Session Status Styles */
.draw-sessions-container {
    margin: 20px 0;
}

.draw-sessions-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 15px;
    max-height: 300px;
    overflow-y: auto;
    padding: 10px;
}

.draw-session-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 2px solid #333;
    border-radius: 12px;
    padding: 15px;
    text-align: center;
    cursor: pointer;
    transition: all 0.3s ease;
    position: relative;
    min-height: 120px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.draw-session-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
}

.draw-session-card.current-session {
    border-color: #00ff88;
    box-shadow: 0 0 15px rgba(0, 255, 136, 0.3);
    position: relative;
}

.current-session-badge {
    position: absolute;
    top: -8px;
    right: -8px;
    background: linear-gradient(135deg, #00ff88 0%, #00cc6a 100%);
    color: #000;
    font-size: 0.7em;
    font-weight: bold;
    padding: 4px 8px;
    border-radius: 12px;
    text-transform: uppercase;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    z-index: 10;
}

.draw-session-card.session-open {
    border-color: #00ff88;
    background: linear-gradient(135deg, #1a5f7a 0%, #0f3460 100%);
}

.draw-session-card.session-closed {
    border-color: #ff4444;
    background: linear-gradient(135deg, #5a1a1a 0%, #3a0f0f 100%);
}

.session-date {
    font-size: 1.4em;
    font-weight: bold;
    color: #fff;
    margin-bottom: 8px;
}

.session-status-badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 12px;
    font-size: 0.8em;
    font-weight: bold;
    margin-bottom: 10px;
    text-transform: uppercase;
}

.session-status-badge.past {
    background-color: #6c757d;
    color: #fff;
}

.session-status-badge.current {
    background-color: #28a745;
    color: #fff;
}

.session-status-badge.future {
    background-color: #17a2b8;
    color: #fff;
}

.session-toggle-status {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: auto;
}

.status-text {
    font-size: 0.9em;
    font-weight: bold;
    color: #fff;
}

.session-open .status-text {
    color: #00ff88;
}

.session-closed .status-text {
    color: #ff4444;
}

.toggle-switch {
    width: 40px;
    height: 20px;
    background-color: #333;
    border-radius: 10px;
    position: relative;
    cursor: pointer;
    transition: background-color 0.3s ease;
}

.toggle-slider {
    width: 16px;
    height: 16px;
    background-color: #fff;
    border-radius: 50%;
    position: absolute;
    top: 2px;
    left: 2px;
    transition: transform 0.3s ease;
}

.toggle-slider.active {
    transform: translateX(20px);
    background-color: #00ff88;
}

.session-open .toggle-switch {
    background-color: #00ff88;
}

.session-closed .toggle-switch {
    background-color: #ff4444;
}
.digit-label {
    font-size: 1.1em;
    font-weight: bold;
    line-height: 1.3;
}
.toggle-indicator {
    position: absolute;
    bottom: 5px;
    right: 5px;
    width: 25px;
    height: 15px;
    background-color: rgba(255, 255, 255, 0.3);
    border-radius: 15px;
    display: flex;
    align-items: center;
    transition: background-color 0.3s ease;
}
.toggle-dot {
    width: 11px;
    height: 11px;
    background-color: white;
    border-radius: 50%;
    transition: transform 0.3s ease;
    transform: translateX(2px);
}
.digit-box-modern.active .toggle-dot {
    transform: translateX(12px);
}

.digits-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(80px, 1fr));
    gap: 10px;
    max-height: 400px;
    overflow-y: auto;
    padding: 15px;
}

.digits-grid .digit-box-modern {
    min-width: 70px;
    min-height: 70px;
    font-size: 0.9rem;
}

.digits-grid .digit-label {
    font-size: 1rem;
}

/* Info Cards Styles */
.limit-result-container {
    margin: 15px 0;
}

.info-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 2px solid #333;
    border-radius: 12px;
    padding: 20px;
    display: flex;
    align-items: center;
    gap: 15px;
    transition: all 0.3s ease;
    min-height: 100px;
}

.info-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
}

.info-card.limit-card {
    border-color: #00ff88;
    background: linear-gradient(135deg, #1a5f7a 0%, #0f3460 100%);
}

.info-card.result-card {
    border-color: #ffd700;
    background: linear-gradient(135deg, #2a1a3a 0%, #1a0f2e 100%);
}

.info-card.no-data-card {
    border-color: #6c757d;
    background: linear-gradient(135deg, #2a2a2a 0%, #1a1a1a 100%);
}

.info-icon {
    width: 50px;
    height: 50px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.5em;
    color: #fff;
    flex-shrink: 0;
}

.limit-card .info-icon {
    background: linear-gradient(135deg, #00ff88 0%, #00cc6a 100%);
}

.result-card .info-icon {
    background: linear-gradient(135deg, #ffd700 0%, #ffb300 100%);
}

.no-data-card .info-icon {
    background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
}

.info-content {
    flex: 1;
}

.info-content h5 {
    color: #fff;
    margin-bottom: 8px;
    font-size: 1.1em;
}

.info-value {
    font-size: 1.8em;
    font-weight: bold;
    color: #00ff88;
    margin-bottom: 5px;
}

.result-details {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.result-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.result-label {
    color: #ccc;
    font-size: 0.9em;
}

.result-value {
    color: #fff;
    font-weight: bold;
    font-size: 0.9em;
}

.result-value.win-number {
    color: #00ff88;
    font-size: 1.1em;
    font-weight: bold;
}

/* Responsive adjustments */
@media (max-width: 768px) {
    .draw-sessions-grid {
        grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
        gap: 10px;
    }
    
    .info-card {
        flex-direction: column;
        text-align: center;
        padding: 15px;
    }
    
    .result-item {
        flex-direction: column;
        align-items: flex-start;
        gap: 2px;
    }
}

</style>
@endsection

@section('content')
    <section class="content-header">
        <div class="container-fluid">
            <div class="row mb-2">
                <div class="col-12">
                    <ol class="breadcrumb float-sm-right">
                        <li class="breadcrumb-item"><a href="{{ route('home') }}">Home</a></li>
                        <li class="breadcrumb-item active">3D Settings</li>
                    </ol>
                </div>
            </div>
        </div>
    </section>

    <!-- Main content -->
    <section class="content">
        <div class="container-fluid">
            <div class="row">
                <div class="col-12">
                    <div class="card justify-content-center">
                        <div class="card-header">
                        <div class="row mt-4">
                        <div class="col-12">
                            <h4 class="mb-3">Manage Draw Sessions</h4>
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                <div class="session-info">
                                    <small class="text-muted">Click any session to toggle open/closed status</small>
                                </div>
                                <div class="session-actions">
                                    <button type="button" class="btn btn-warning btn-sm" onclick="triggerSessionTransition()">
                                        <i class="fas fa-sync-alt"></i> Auto Transition Sessions
                                    </button>
                                </div>
                            </div>
                            <div class="draw-sessions-container">
                                <div class="draw-sessions-grid">
                                    @foreach($drawSessions as $session)
                                        <div class="draw-session-card {{ $session['status'] == 'current' ? 'current-session' : '' }} {{ $session['is_open'] ? 'session-open' : 'session-closed' }}"
                                            data-date="{{ $session['date'] }}"
                                            data-status="{{ $session['status'] }}"
                                            data-is-open="{{ $session['is_open'] ? '1' : '0' }}"
                                            title="Draw Session: {{ $session['date'] }} ({{ ucfirst($session['status']) }}) - {{ $session['is_open'] ? 'Open' : 'Closed' }}"
                                            onclick="toggleDrawSession('{{ $session['date'] }}', {{ $session['is_open'] ? 'false' : 'true' }})">
                                            @if($session['status'] == 'current')
                                                <div class="current-session-badge">CURRENT</div>
                                            @endif
                                            <div class="session-date">{{ \Carbon\Carbon::parse($session['date'])->format('M d') }}</div>
                                            <div class="session-status-badge {{ $session['status'] }}">
                                                {{ ucfirst($session['status']) }}
                                            </div>
                                            <div class="session-toggle-status">
                                                <span class="status-text">{{ $session['is_open'] ? 'Open' : 'Closed' }}</span>
                                                <div class="toggle-switch">
                                                    <div class="toggle-slider {{ $session['is_open'] ? 'active' : '' }}"></div>
                                                </div>
                                            </div>
                                        </div>
                                    @endforeach
                                </div>
                            </div>
                        </div>
                        </div>
                        <div class="row mt-4">
                        <div class="col-md-6">
                            <h4 class="mb-3">Manage ThreeD Limit (Break)</h4>
                            <div class="limit-result-container">
                                @if($threeDLimit)
                                    <div class="info-card limit-card">
                                        <div class="info-icon">
                                            <i class="fas fa-chart-line"></i>
                                        </div>
                                        <div class="info-content">
                                            <h5>Current Limit</h5>
                                            <div class="info-value">{{ number_format($threeDLimit->max_total_bet, 0, '.', ',') }}</div>
                                            <small class="text-muted">Max Total Bet Amount</small>
                                        </div>
                                    </div>
                                @else
                                    <div class="info-card no-data-card">
                                        <div class="info-icon">
                                            <i class="fas fa-exclamation-triangle"></i>
                                        </div>
                                        <div class="info-content">
                                            <h5>No Limit Set</h5>
                                            <small class="text-muted">Please set a 3D limit</small>
                                        </div>
                                    </div>
                                @endif
                            </div>
                        </div>

                        <div class="col-md-6">
                            <h4 class="mb-3">Manage ThreeD Result</h4>
                            <div class="limit-result-container">
                                @if($threeDResult)
                                    <div class="info-card result-card">
                                        <div class="info-icon">
                                            <i class="fas fa-trophy"></i>
                                        </div>
                                        <div class="info-content">
                                            <h5>Latest Result</h5>
                                            <div class="result-details">
                                                <div class="result-item">
                                                    <span class="result-label">Win Number:</span>
                                                    <span class="result-value win-number">{{ $threeDResult->win_number }}</span>
                                                </div>
                                                <div class="result-item">
                                                    <span class="result-label">Session:</span>
                                                    <span class="result-value">{{ $threeDResult->draw_session }}</span>
                                                </div>
                                                <div class="result-item">
                                                    <span class="result-label">Date:</span>
                                                    <span class="result-value">{{ $threeDResult->result_date }}</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                @else
                                    <div class="info-card no-data-card">
                                        <div class="info-icon">
                                            <i class="fas fa-clock"></i>
                                        </div>
                                        <div class="info-content">
                                            <h5>No Result Yet</h5>
                                            <small class="text-muted">No 3D result has been declared</small>
                                        </div>
                                    </div>
                                @endif
                            </div>
                        </div>
                        </div>
                        <div class="d-flex justify-content-center mt-3">
                            <button type="button" class="btn btn-success mx-2 px-4 py-2" data-toggle="modal" data-target="#threeDLimitModal">
                                <i class="fas fa-plus text-white mr-2"></i> Add ThreeD Limit (Break)
                            </button>
                            <button type="button" class="btn btn-primary mx-2 px-4 py-2" data-toggle="modal" data-target="#threeDResultModal">
                                <i class="fas fa-plus text-white mr-2"></i> Add ThreeD Result
                            </button>
                         </div>                      
                    </div>

                            </div>
                        </div>
                        <div class="card-body justify-content-center">
                            <!-- Break Groups Display -->
                            <div class="break-groups-container">
                                <h5 class="mb-3">Break Groups (Digit Sum Categories)</h5>
                                <div class="digits-flex-container">
                                    @for($i = 0; $i <= 27; $i++)
                                        <div class="digit-item">
                                            <div class="digit-number">Break {{ $i }}</div>
                                            <div class="digit-status">
                                                <span class="status-text text-info">
                                                    {{ $breakGroupCounts[$i] ?? 0 }} numbers
                                                </span>
                                            </div>
                                        </div>
                                    @endfor
                                </div>
                            </div>

                            <div class="horizontal-bar">
                                @for($i = 0; $i <= 27; $i++)
                                    <div class="digit-box">
                                        {{ $i }}
                                    </div>
                                @endfor
                        </div>
                            </div>
                        </div>
                    </div>

                    <!-- 3D Close Digits Section -->
                    <div class="card mt-4">
                        <div class="card-header">
                            <h3 class="card-title">3D Close Digits Management (000-999)</h3>
                            <div class="card-tools">
                                <!-- <button type="button" class="btn btn-sm btn-success" onclick="openAllDigits()">
                                    <i class="fas fa-unlock"></i> Open All
                                </button>
                                <button type="button" class="btn btn-sm btn-danger" onclick="closeAllDigits()">
                                    <i class="fas fa-lock"></i> Close All
                                </button> -->
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-12">
                                    <div class="digits-grid" id="threeDCloseDigitsGrid">
                                        @foreach($threeDCloseDigits as $digit)
                                            <div class="digit-box-modern {{ $digit->status ? 'active' : '' }}" 
                                                 data-digit="{{ $digit->close_digit }}"
                                                 onclick="toggleDigit('{{ $digit->close_digit }}')"
                                                 title="3D Digit: {{ $digit->close_digit }} ({{ $digit->status ? 'Open' : 'Closed' }})">
                                                <span class="digit-label">{{ $digit->close_digit }}</span>
                                                <span class="toggle-indicator">
                                                    <span class="toggle-dot"></span>
                                                </span>
                                            </div>
                                        @endforeach
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card mt-4">
                        <div class="card-header">
                            <h3 class="card-title">Quick Selection Patterns</h3>
                        </div>
                        <div class="card-body">
                            <div class="choose-digit-section">
                                <div class="choose-digit-title">Quick Selection Patterns</div>
                               

                                <div class="horizontal-bar-group">
                        @foreach($quickPatterns->chunk(10) as $chunk)
                            <div class="horizontal-bar-modern">
                                @foreach($chunk as $pattern)
                                    <div class="digit-box-modern"
                                        data-pattern="{{ $pattern['name'] }}"
                                        title="Quick Pattern: {{ $pattern['name'] }}">
                                        <span class="digit-label">{{ $pattern['name'] }}</span>
                                        <span class="toggle-indicator">
                                            <span class="toggle-dot"></span>
                                        </span>
                                    </div>
                                @endforeach
                            </div>
                        @endforeach
                    </div>
                            </div>
                        </div>
                    </div>

        </div>
    </section>

    <!-- ThreeD Result Modal -->
    <div class="modal fade" id="threeDResultModal" tabindex="-1" role="dialog" aria-labelledby="threeDResultModalLabel" aria-modal="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="threeDResultModalLabel">Add ThreeD Result</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <form action="{{ route('admin.three-d-result.store') }}" method="POST" autocomplete="off">
                    @csrf
                    <div class="modal-body">
                        <div class="form-group">
                            <label for="win_number">ThreeD Result (000-999)</label>
                            <input type="text" class="form-control @error('win_number') is-invalid @enderror" 
                                   id="win_number" name="win_number" 
                                   placeholder="Enter 3-digit number (000-999)" required aria-required="true"
                                   pattern="[0-9]{3}" maxlength="3">
                            @error('win_number')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                        </div>
                        <div class="form-group">
                            <label for="draw_session">Draw Session</label>
                            <select class="form-control @error('draw_session') is-invalid @enderror" 
                                   id="draw_session" name="draw_session" required aria-required="true">
                                <option value="">Select draw session</option>
                                @foreach($availableDrawSessions as $session)
                                    <option value="{{ $session }}">{{ $session }}</option>
                                @endforeach
                            </select>
                            @error('draw_session')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                        </div>
                        <div class="form-group">
                            <label for="result_date">Result Date</label>
                            <input type="date" class="form-control @error('result_date') is-invalid @enderror" 
                                   id="result_date" name="result_date" required aria-required="true">    
                            @error('result_date')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                        </div>
                        <div class="form-group">
                            <label for="result_time">Result Time</label>
                            <input type="time" class="form-control @error('result_time') is-invalid @enderror" 
                                   id="result_time" name="result_time" required aria-required="true">
                            @error('result_time')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                        </div>
                       
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button type="submit" class="btn btn-success">Add ThreeD Result</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- ThreeD Limit Modal -->
    <div class="modal fade" id="threeDLimitModal" tabindex="-1" role="dialog" aria-labelledby="threeDLimitModalLabel" aria-modal="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="threeDLimitModalLabel">Add ThreeD Limit (Break)</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <form action="{{ route('admin.three-d-limit.store') }}" method="POST" autocomplete="off">
                    @csrf
                    <div class="modal-body">
                        <div class="form-group">
                            <label for="min_bet_amount">Minimum Bet Amount</label>
                            <input type="number" step="0.01" class="form-control @error('min_bet_amount') is-invalid @enderror" 
                                   id="min_bet_amount" name="min_bet_amount" 
                                   placeholder="Enter minimum bet amount" required aria-required="true"
                                   value="{{ old('min_bet_amount', 1.00) }}">
                            @error('min_bet_amount')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                        </div>
                        <div class="form-group">
                            <label for="max_bet_amount">Maximum Bet Amount</label>
                            <input type="number" step="0.01" class="form-control @error('max_bet_amount') is-invalid @enderror" 
                                   id="max_bet_amount" name="max_bet_amount" 
                                   placeholder="Enter maximum bet amount" required aria-required="true"
                                   value="{{ old('max_bet_amount', 10000.00) }}">
                            @error('max_bet_amount')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                        </div>
                        <div class="form-group">
                            <label for="max_total_bet">Maximum Total Bet (Break)</label>
                            <input type="number" step="0.01" class="form-control @error('max_total_bet') is-invalid @enderror" 
                                   id="max_total_bet" name="max_total_bet" 
                                   placeholder="Enter maximum total bet limit" required aria-required="true"
                                   value="{{ old('max_total_bet', 100000.00) }}">
                            @error('max_total_bet')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                        </div>
                        <div class="form-group">
                            <label for="payout_multiplier">Payout Multiplier (800x)</label>
                            <input type="number" step="0.01" class="form-control @error('payout_multiplier') is-invalid @enderror" 
                                   id="payout_multiplier" name="payout_multiplier" 
                                   placeholder="Enter payout multiplier" required aria-required="true"
                                   value="{{ old('payout_multiplier', 800.00) }}">
                            @error('payout_multiplier')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button type="submit" class="btn btn-success">Add ThreeD Limit (Break)</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
@endsection

@section('script')
<link href="{{ asset('plugins/select2/css/select2.min.css') }}" rel="stylesheet" />
<script src="{{ asset('plugins/jquery/jquery.min.js') }}"></script>
<script src="{{ asset('plugins/select2/js/select2.full.min.js') }}"></script>
<script src="{{ asset('plugins/sweetalert2/sweetalert2.min.js') }}"></script>
<script src="{{ asset('plugins/datatables/jquery.dataTables.min.js') }}"></script>
<link href="{{ asset('plugins/datatables-buttons/css/buttons.bootstrap4.min.css') }}" rel="stylesheet" />
<script src="{{ asset('plugins/datatables-buttons/js/dataTables.buttons.min.js') }}"></script>
<script src="{{ asset('plugins/datatables-buttons/js/buttons.bootstrap4.min.js') }}"></script>
<script src="{{ asset('plugins/datatables-buttons/js/buttons.html5.min.js') }}"></script>
<script src="{{ asset('plugins/datatables-buttons/js/buttons.print.min.js') }}"></script>
<script src="{{ asset('plugins/datatables-buttons/js/buttons.colVis.min.js') }}"></script>
<script>
$(document).ready(function() {
    // Clear form when modal is closed
    $('#threeDLimitModal').on('hidden.bs.modal', function () {
        $(this).find('form')[0].reset();
    });
    
    $('#threeDResultModal').on('hidden.bs.modal', function () {
        $(this).find('form')[0].reset();
    });
});

// Function to show a custom message box instead of alert()
function showMessageBox(message, type = 'info') {
    const messageBox = document.createElement('div');
    messageBox.style.cssText = `
        position: fixed;
        top: 100px;
        right: 10px;
        background-color: ${type === 'success' ? '#4CAF50' : '#f44336'};
        color: white;
        padding: 15px;
        border-radius: 5px;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
        z-index: 1000;
        opacity: 0;
        transition: opacity 0.5s ease-in-out;
    `;
    messageBox.textContent = message;
    document.body.appendChild(messageBox);

    // Fade in
    setTimeout(() => messageBox.style.opacity = '1', 10);

    // Fade out and remove after 3 seconds
    setTimeout(() => {
        messageBox.style.opacity = '0';
        messageBox.addEventListener('transitionend', () => messageBox.remove());
    }, 3000);
}

document.addEventListener('DOMContentLoaded', function() {
    const drawSessionSelect = document.getElementById('draw_session');
    const resultDateInput = document.getElementById('result_date');
    const resultTimeInput = document.getElementById('result_time');
    
    function setDateBySession() {
        if (drawSessionSelect.value) {
            resultDateInput.value = drawSessionSelect.value;
            resultTimeInput.value = '15:30'; // Default draw time
        }
    }
    
    if (drawSessionSelect && resultDateInput && resultTimeInput) {
        drawSessionSelect.addEventListener('change', setDateBySession);
        setDateBySession(); // set on load
    }
});

// 3D Close Digits Functions
function toggleDigit(digit) {
    $.ajax({
        url: '{{ route("admin.three-d-close-digit.toggle-status") }}',
        type: 'POST',
        data: {
            close_digit: digit,
            _token: '{{ csrf_token() }}'
        },
        success: function(response) {
            if (response.success) {
                const digitBox = document.querySelector(`[data-digit="${digit}"]`);
                if (digitBox) {
                    digitBox.classList.toggle('active');
                    const statusText = response.data.status ? 'Open' : 'Closed';
                    digitBox.title = `3D Digit: ${digit} (${statusText})`;
                    showMessageBox(`Digit ${digit} is now ${statusText}`, 'success');
                }
            } else {
                showMessageBox(response.message || 'Error updating digit status', 'error');
            }
        },
        error: function(xhr) {
            showMessageBox('Error updating digit status', 'error');
        }
    });
}

function openAllDigits() {
    if (confirm('Are you sure you want to open all 3D digits?')) {
        // This would need a bulk update endpoint
        showMessageBox('Opening all digits...', 'info');
        // TODO: Implement bulk open functionality
    }
}

function closeAllDigits() {
    if (confirm('Are you sure you want to close all 3D digits?')) {
        // This would need a bulk update endpoint
        showMessageBox('Closing all digits...', 'info');
        // TODO: Implement bulk close functionality
    }
}

// Draw Session Toggle Function
function toggleDrawSession(date, newIsOpen) {
    const sessionCard = document.querySelector(`.draw-session-card[data-date="${date}"]`);
    if (sessionCard) {
        // Convert to proper boolean value
        const isOpen = newIsOpen === true || newIsOpen === 'true' || newIsOpen === 1;

        $.ajax({
            url: '{{ route("admin.three-d-draw-session.toggle-status") }}',
            type: 'POST',
            data: {
                draw_session: date,
                is_open: isOpen,
                _token: '{{ csrf_token() }}'
            },
            success: function(response) {
                if (response.success) {
                    // Update card classes
                    sessionCard.classList.toggle('session-open', isOpen);
                    sessionCard.classList.toggle('session-closed', !isOpen);
                    sessionCard.dataset.isOpen = isOpen ? '1' : '0';
                    
                    // Update the status text
                    const statusElement = sessionCard.querySelector('.status-text');
                    if (statusElement) {
                        statusElement.textContent = isOpen ? 'Open' : 'Closed';
                    }
                    
                    // Update toggle slider
                    const toggleSlider = sessionCard.querySelector('.toggle-slider');
                    if (toggleSlider) {
                        toggleSlider.classList.toggle('active', isOpen);
                    }
                    
                    // Update title
                    sessionCard.title = `Draw Session: ${date} - ${isOpen ? 'Open' : 'Closed'}`;
                    
                    showMessageBox(`Draw session for ${date} is now ${isOpen ? 'Open' : 'Closed'}`, 'success');
                } else {
                    showMessageBox(response.message || 'Error toggling draw session status', 'error');
                }
            },
            error: function(xhr) {
                console.error('Error:', xhr.responseText);
                let errorMessage = 'Error toggling draw session status';
                
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (response.message) {
                        errorMessage = response.message;
                    } else if (response.errors && response.errors.is_open) {
                        errorMessage = response.errors.is_open[0];
                    }
                } catch (e) {
                    // If JSON parsing fails, use default message
                }
                
                showMessageBox(errorMessage, 'error');
            }
        });
    }
}

// Trigger Session Transition Function
function triggerSessionTransition() {
    if (!confirm('This will automatically close the current draw session (if past 2:30 PM) and open the next draw session. Continue?')) {
        return;
    }

    $.ajax({
        url: '{{ route("admin.three-d-draw-session.trigger-transition") }}',
        type: 'POST',
        data: {
            _token: '{{ csrf_token() }}'
        },
        success: function(response) {
            if (response.success) {
                showMessageBox(response.message, 'success');
                
                // Show details if available
                if (response.details && response.details.length > 0) {
                    let details = response.details.join('\n');
                    setTimeout(() => {
                        alert('Transition Details:\n' + details);
                    }, 1000);
                }
                
                // Reload the page to show updated status
                setTimeout(() => {
                    location.reload();
                }, 2000);
            } else {
                showMessageBox(response.message || 'Error triggering session transition', 'error');
            }
        },
        error: function(xhr) {
            console.error('Error:', xhr.responseText);
            showMessageBox('Error triggering session transition', 'error');
        }
    });
}
</script>

@if (session()->has('success'))
    <script>
        Swal.fire({
            icon: 'success',
            title: '{{ session('success') }}',
            showConfirmButton: false,
            timer: 1500
        });
    </script>
@endif
@endsection

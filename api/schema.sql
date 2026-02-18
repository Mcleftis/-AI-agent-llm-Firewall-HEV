-- apothikefsi dedomenwn apo to oxhma
CREATE TABLE IF NOT EXISTS telemetry ( --dimiourgei table me onoma telemetry mono an den yparxei idi.
    id INTEGER PRIMARY KEY AUTOINCREMENT,  --id: integer, primary key, kai aytomata auksanetai se kathe nea eggrafi.
    timestamp TEXT NOT NULL,               --timestamp: keimeno pou periexei imerominia‑ora (synithos ISO 8601).NOT NULL: prepei ypoxreotika na yparxei.
    speed_kmh REAL,                        --Taxytita tou oximatos se km/h. REAL = float
    battery_soc REAL,                      
    motor_temp REAL,                       
    log_source TEXT DEFAULT 'API'          -- Apo pou hrthe h eggrafh(API/Simulation)
);

--Create Indexes (Optimization)
-- Ftiaxnoume evretirio sto timestamp
CREATE INDEX IF NOT EXISTS idx_timestamp ON telemetry(timestamp);--Ftiaxnei index me onoma idx_timestamp sto pedio timestamp. An yparxei idi, den to ksanaftiaxnei.

-- ==========================================
-- Example Queries (Για Documentation)
-- ==========================================

-- Q1: Get average speed
-- SELECT AVG(speed_kmh) FROM telemetry;

-- Q2: Find moments of high motor temperature (> 90C)
-- SELECT * FROM telemetry WHERE motor_temp > 90.0;
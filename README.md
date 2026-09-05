# Norma — Traffic Anomaly Detection Engine

Norma is a real-time traffic monitoring engine that continuously learns what normal traffic looks like, detects unusual behavior, and automatically responds to potential threats.

## How It Works

Norma continuously observes incoming traffic and builds a picture of normal behavior.

When traffic significantly deviates from that baseline, Norma can:

* Identify the source of the unusual activity
* Block the source automatically
* Send an alert
* Record the event
* Increase the response duration if the behavior continues

```text
Traffic
   ↓
Monitor activity
   ↓
Learn normal behavior
   ↓
Detect unusual patterns
   ↓
Take action
   ↓
Monitor the result
```

## Key Features

* Real-time traffic monitoring
* Automatic baseline learning
* Per-source and overall traffic analysis
* Anomaly detection
* Automatic blocking
* Progressive response to repeated anomalies
* Alerting
* Audit logging
* Live monitoring dashboard

## Detection Model

Norma doesn't rely on a fixed definition of "bad traffic."

Instead, it learns from recent traffic and establishes a baseline of normal activity. New traffic is continuously compared against that baseline.

This allows Norma to detect changes in behavior rather than simply looking for predefined rules.

## Response

When suspicious activity is detected, Norma can automatically respond by blocking the source and recording the event.

Repeated abnormal behavior results in progressively longer restrictions:

```text
10 minutes
    ↓
30 minutes
    ↓
2 hours
    ↓
Permanent
```

Trusted sources can be excluded from automatic blocking through a whitelist.



## Dashboard

Norma includes a live dashboard for observing system activity, including:

* Current traffic levels
* Top traffic sources
* Active blocks
* Learned traffic baseline
* System status
* Service uptime

## Technology

* Python
* Nginx
* FastAPI
* Docker
* PostgreSQL

## Project Status

Norma is currently under active development.

The goal is to build a lightweight traffic intelligence engine that can observe a system, understand its normal behavior, identify meaningful deviations, and respond automatically.

# Data Flow Diagrams
## DMV Scam Analysis Project

### Overview
This document provides data flow diagrams illustrating the interaction between various analysis tools within the DMV scam analysis project.

## Data Extraction and Processing
```mermaid
graph TD;
    A[Extract Messages (message_extractor.py)] --2 CSV --> B[Process Data (process_raw_data.py)];
    B -- Cleaned Data --> C[Sentiment Analysis (sentiment_analyzer.py)];
    C -- Results --> D[Validate IOCs (ioc_validator.py)];
```

## Analysis and Visualization
```mermaid
graph TD;
    D -- Validated IOCs --> E[Visualize Threats (threat_visualizer.py)];
    E -- Visual Data --> F[Generate Reports (generate_reports.py)];
```

## End-to-End Workflow
```mermaid
graph TD;
    A[Start] -->|Extract & Process| B[Data Pipeline];
    B -->|Analysis| C[Sentiment & IOC Validation];
    C -->|Visualization| D[Dashboard Generation];
    D -->|Reporting| E[Final Reports];
```

## Integration and Execution
```mermaid
graph TD;
    subgraph Environment Setup
    A1[Python Environment] -- Setup --> A2[Database Configuration]
    end
    
    subgraph Automation
    B1[Cron Jobs] -- Scheduled Run --> B2[Analysis Scripts]
    end

    A2 --> B2;
    B2 -->|Triggers| C1[Execution Logs];
    B2 -->|Outputs| C2[Results & Visualizations];
    C2 --> C3[Report Distribution];
```

## Detailed Technical Flow
```mermaid
graph TD;
    subgraph Data Extraction
        A1[SQLite DB] -->|Raw Messages| A2[message_extractor.py];
        A2 -->|DataFrame| A3[CSV Output];
    end

    subgraph Data Processing
        B1[process_raw_data.py] -->|Text Cleaning| B2[Sanitized Data];
        B2 -->|Feature Extraction| B3[Processed Features];
    end

    subgraph Analysis
        C1[sentiment_analyzer.py] -->|NLTK Processing| C2[Sentiment Scores];
        C2 -->|Pattern Matching| C3[Threat Patterns];
        C3 -->|Validation| C4[ioc_validator.py];
    end

    subgraph Visualization
        D1[threat_visualizer.py] -->|Plotly| D2[Interactive Dashboards];
        D1 -->|Matplotlib| D3[Static Plots];
        D2 -->|HTML| D4[Web Interface];
        D3 -->|PNG/PDF| D5[Report Graphics];
    end

    A3 --> B1;
    B3 --> C1;
    C4 --> D1;
```

## Data Transformations
```mermaid
graph LR;
    subgraph Input
        A1[Raw Messages] -->|Extraction| A2[JSON/Dict];
    end

    subgraph Processing
        B1[DataFrame] -->|Cleaning| B2[Processed DF];
        B2 -->|Feature Engineering| B3[Feature Matrix];
    end

    subgraph Analysis
        C1[Feature Vector] -->|ML Model| C2[Predictions];
        C2 -->|Aggregation| C3[Results];
    end

    subgraph Output
        D1[Analysis Results] -->|Formatting| D2[Reports];
        D1 -->|Visualization| D3[Dashboards];
    end

    A2 --> B1;
    B3 --> C1;
    C3 --> D1;
```

### Legend
- **Nodes**: Represent steps or tools in the data flow
- **Edges**: Indicate data or process flow between nodes
- **Subgraphs**: Group related components or functions

---

**Document Version**: 1.0  
**Last Updated**: June 2025  
**Status**: Active  
**Review Date**: December 2025

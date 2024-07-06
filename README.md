## Intrusion Detection System with Machine Learning and Flask

This repository implements a web-based Intrusion Detection System (IDS) simulator using Machine Learning (ML) and Flask. Security researchers and scholars can utilize this platform to:

* Simulate various network attack scenarios.
* Observe the behavior of trained ML models in detecting these attacks.
* Gain insights into the effectiveness of different ML algorithms for intrusion detection.

### Features

* User-friendly web interface built with Flask.
* Allows simulating different attack types (e.g., DoS, DDoS, Port Scans).
* Integrates a pre-trained ML model for real-time attack detection.
* Provides detailed analysis of the model's predictions.
* Supports uploading custom network traffic data for analysis.

### Benefits

* Offers a controlled environment for testing and evaluating ML-based intrusion detection systems.
* Enables researchers to experiment with diverse attack scenarios.
* Provides valuable insights for improving the accuracy and robustness of ML models.

### Getting Started

1. **Prerequisites:**
    * Python 3.x
    * Necessary libraries (listed in `requirements.txt`)
        * Install them using: `pip install -r requirements.txt`

2. **Model Loading:**
    * A pre-trained ML model for intrusion detection is required. 
    * Place the model file in the `ML Models` directory.

3. **Running the Application:**
    * Start the Flask development server:
        ```bash
        python start.py
        ```
        * Access the application at `http://localhost:5000` (default port) by default.

### Usage

* The web interface allows users to:
    * Select a pre-defined attack scenario or upload custom network traffic data.
    * Initiate the simulation.
    * View the results, including:
        * Model prediction (attack or normal traffic).
        * Confidence score associated with the prediction.
        * Visualization of relevant network features used for detection.


### License

This project is licensed under the MIT License. See `LICENSE` for details.

### Disclaimer

This is a research tool for educational purposes only. It does not represent a production-ready IDS and should not be solely relied upon for real-world security.

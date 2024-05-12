import sys
import pickle
import numpy as np
import re
import string
from urllib.parse import urlparse
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel
from PyQt5 import QtCore



class MaliciousURLChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Malicious URL Checker')

        # Input URL field
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter URL")

        # Button to check URL
        self.check_button = QPushButton('Check', self)
        self.check_button.clicked.connect(self.check_url)

        # Display label for result
        self.result_label = QLabel('', self)
        self.result_label.setAlignment(QtCore.Qt.AlignCenter)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.url_input)
        layout.addWidget(self.check_button)
        layout.addWidget(self.result_label)
        self.setLayout(layout)

        self.show()

    def create_features(self, url):
        features = []

        # Count occurrences of specific characters in the URL
        feature_characters = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
        for char in feature_characters:
            features.append(url.count(char))

        # Check if the URL contains the hostname
        hostname = str(urlparse(url).hostname)
        match = re.search(hostname, url)
        features.append(1 if match else 0)

        # Check if the URL uses HTTPS
        scheme = urlparse(url).scheme
        features.append(1 if scheme == 'https' else 0)

        # Count the number of digits in the URL
        digits = sum(ch.isdigit() for ch in url)
        features.append(digits)

        # Count the number of special characters in the URL
        special_chars = sum(ch in string.punctuation for ch in url)
        features.append(special_chars)

        # Count the number of letters in the URL
        letters = sum(ch.isalpha() for ch in url)
        features.append(letters)

        # Check if the URL is shortened
        shortened_patterns = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co']
        shortened = any(pattern in url for pattern in shortened_patterns)
        features.append(1 if shortened else 0)

        # Check if the URL contains an IP address
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        contains_ip = bool(re.search(ip_pattern, url))
        features.append(1 if contains_ip else 0)

        return np.array(features).reshape(1, -1)

    def check_url(self):
        url = self.url_input.text()

        # Load the trained model
        with open('random_forest.pkl', 'rb') as file:
            loaded_model = pickle.load(file)

        # Create features from the URL
        X_new = self.create_features(url)

        # Make predictions using the loaded model
        prediction = loaded_model.predict(X_new)

        # Display the result
        if prediction[0] == 0:
            self.result_label.setText("Not malicious")
        else:
            self.result_label.setText("Malicious")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MaliciousURLChecker()
    sys.exit(app.exec_())

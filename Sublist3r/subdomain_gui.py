import sys
import validators
import logging
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QFileDialog,
    QProgressBar,
    QHBoxLayout,
    QSpinBox,
    QStatusBar,
    QMessageBox,
)
from PyQt5.QtCore import Qt, QSettings, pyqtSlot
from subdomain_logic import SubdomainEnumerationThread

logging.basicConfig(level=logging.INFO)


class SubdomainEnumerator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.subdomains = []
        self.current_page = 0
        self.items_per_page = 10

        self.settings = QSettings("MyApp", "SubdomainEnumerator")
        self.script_path = self.settings.value("scriptPath", "")
        self.items_per_page = int(self.settings.value("itemsPerPage", 10))

        self.initUI()

    def initUI(self):
        self.setWindowTitle("Subdomain Enumerator")
        self.setGeometry(100, 100, 600, 600)

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)

        mainWidget = QWidget()
        self.setCentralWidget(mainWidget)
        layout = QVBoxLayout()

        self.domainLabel = QLabel("Enter the domain:")
        layout.addWidget(self.domainLabel)

        self.domainInput = QLineEdit()
        self.domainInput.setToolTip(
            "Enter the domain to enumerate subdomains.")
        layout.addWidget(self.domainInput)

        self.enumerateButton = QPushButton("Enumerate Subdomains")
        self.enumerateButton.clicked.connect(self.enumerate_subdomains)
        self.enumerateButton.setToolTip(
            "Click to start enumerating subdomains.")
        layout.addWidget(self.enumerateButton)

        self.saveButton = QPushButton("Save Results")
        self.saveButton.clicked.connect(self.save_results)
        self.saveButton.setToolTip(
            "Click to save the enumerated subdomains to a file.")
        layout.addWidget(self.saveButton)

        self.progressLabel = QLabel("")
        layout.addWidget(self.progressLabel)

        self.progressBar = QProgressBar(self)
        self.progressBar.setMaximum(100)
        layout.addWidget(self.progressBar)

        self.resultArea = QTextEdit()
        self.resultArea.setReadOnly(True)
        layout.addWidget(self.resultArea)

        paginationLayout = QHBoxLayout()
        self.prevButton = QPushButton("Previous")
        self.prevButton.clicked.connect(self.show_previous_page)
        self.prevButton.setEnabled(False)
        paginationLayout.addWidget(self.prevButton)

        self.pageLabel = QLabel("Page 0/0")
        paginationLayout.addWidget(self.pageLabel)

        self.nextButton = QPushButton("Next")
        self.nextButton.clicked.connect(self.show_next_page)
        self.nextButton.setEnabled(False)
        paginationLayout.addWidget(self.nextButton)
        layout.addLayout(paginationLayout)

        self.itemsPerPageLabel = QLabel("Items per page:")
        layout.addWidget(self.itemsPerPageLabel)

        self.itemsPerPageSpinBox = QSpinBox()
        self.itemsPerPageSpinBox.setValue(self.items_per_page)
        self.itemsPerPageSpinBox.valueChanged.connect(
            self.update_items_per_page)
        layout.addWidget(self.itemsPerPageSpinBox)

        self.scriptPathButton = QPushButton("Set Sublist3r Path")
        self.scriptPathButton.clicked.connect(self.set_script_path)
        layout.addWidget(self.scriptPathButton)

        mainWidget.setLayout(layout)

    def normalize_domain(self, domain):
        # Remove http:// or https:// from the domain if present
        if domain.startswith("http://"):
            domain = domain[len("http://"):]
        elif domain.startswith("https://"):
            domain = domain[len("https://"):]
        return domain

    def validate_domain(self, domain):
        # Validate the domain using the validators library
        return validators.domain(domain)

    def enumerate_subdomains(self):
        domain = self.domainInput.text().strip()
        self.resultArea.clear()
        self.progressBar.setValue(0)

        if domain:
            domain = self.normalize_domain(domain)
            if not self.validate_domain(domain):
                self.resultArea.append(
                    "Invalid domain format. Please enter a valid domain."
                )
                return

            self.progressLabel.setText("Starting enumeration...")
            self.enumerateButton.setEnabled(False)
            self.saveButton.setEnabled(False)
            logging.info(f"Starting enumeration for domain: {domain}")
            self.enumerationThread = SubdomainEnumerationThread(
                domain, self.script_path
            )
            self.enumerationThread.finished.connect(
                self.on_enumeration_finished)
            self.enumerationThread.error.connect(self.on_enumeration_error)
            self.enumerationThread.progress.connect(self.on_progress)
            self.enumerationThread.update_progress.connect(
                self.on_update_progress)
            self.enumerationThread.start()
        else:
            self.resultArea.append("Please enter a domain.")

    @pyqtSlot(int)
    def on_progress(self, value):
        self.progressBar.setValue(value)
        self.statusBar.showMessage(f"Progress: {value}%")
        logging.info(f"Progress: {value}%")

    @pyqtSlot(int, str)
    def on_update_progress(self, value, message):
        self.progressBar.setValue(value)
        self.progressLabel.setText(message)
        self.statusBar.showMessage(message)
        logging.info(f"Progress: {value}% - {message}")

    @pyqtSlot(list)
    def on_enumeration_finished(self, subdomains):
        self.subdomains = subdomains
        self.current_page = 0
        self.enumerateButton.setEnabled(True)
        self.saveButton.setEnabled(True)
        self.update_pagination()
        self.show_page(self.current_page)
        self.progressBar.setValue(100)
        self.statusBar.showMessage("Enumeration completed.")
        logging.info("Enumeration completed.")
        if subdomains:
            self.nextButton.setEnabled(len(subdomains) > self.items_per_page)
        else:
            self.resultArea.append("No subdomains found.")

    @pyqtSlot(str)
    def on_enumeration_error(self, errorMsg):
        self.progressLabel.setText("Error during enumeration.")
        self.enumerateButton.setEnabled(True)
        self.saveButton.setEnabled(True)
        self.resultArea.append("Error during enumeration:\n" + errorMsg)
        self.statusBar.showMessage("Error during enumeration.")
        self.progressBar.setValue(0)
        QMessageBox.critical(self, "Error", errorMsg)
        logging.error(f"Error during enumeration: {errorMsg}")

    def update_pagination(self):
        total_pages = (
            len(self.subdomains) + self.items_per_page - 1
        ) // self.items_per_page
        self.pageLabel.setText(f"Page {self.current_page + 1}/{total_pages}")
        self.prevButton.setEnabled(self.current_page > 0)
        self.nextButton.setEnabled(
            (self.current_page + 1) * self.items_per_page < len(self.subdomains)
        )

    def show_page(self, page):
        self.resultArea.clear()
        start_index = page * self.items_per_page
        end_index = start_index + self.items_per_page
        for subdomain in self.subdomains[start_index:end_index]:
            self.resultArea.append(subdomain)
        self.update_pagination()

    def show_previous_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.show_page(self.current_page)

    def show_next_page(self):
        if (self.current_page + 1) * self.items_per_page < len(self.subdomains):
            self.current_page += 1
            self.show_page(self.current_page)

    def update_items_per_page(self):
        self.items_per_page = self.itemsPerPageSpinBox.value()
        self.settings.setValue(
            "itemsPerPage", self.items_per_page
        )  # Save items per page setting
        self.show_page(self.current_page)

    def save_results(self):
        if not self.subdomains:
            self.resultArea.append("No subdomains to save.")
            return
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Save Subdomains",
            "",
            "Text Files (*.txt);;All Files (*)",
            options=options,
        )
        if file_name:
            try:
                with open(file_name, "w") as file:
                    for subdomain in self.subdomains:
                        file.write(subdomain + "\n")
                self.statusBar.showMessage("Subdomains saved successfully.")
                logging.info(f"Subdomains saved to {file_name}")
            except Exception as e:
                self.resultArea.append("Error saving subdomains:\n" + str(e))
                self.statusBar.showMessage("Error saving subdomains.")
                logging.error(f"Error saving subdomains: {e}")

    def set_script_path(self):
        options = QFileDialog.Options()
        script_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Sublist3r Script",
            "",
            "Python Files (*.py);;All Files (*)",
            options=options,
        )
        if script_path:
            self.script_path = script_path
            self.settings.setValue(
                "scriptPath", self.script_path
            )  # Save script path setting
            self.statusBar.showMessage(
                f"Script path set to: {self.script_path}")
            logging.info(f"Script path set to: {self.script_path}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = SubdomainEnumerator()
    main_window.show()
    sys.exit(app.exec_())

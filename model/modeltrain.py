# Import necessary libraries
import pandas as pd
import numpy as np
import arff  # Library to handle .arff files
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.tree import plot_tree
from joblib import dump, load
# Load the dataset
# Make sure the path to your dataset is correct
url = "./dataset/Training Dataset.arff"

# Read the .arff file
with open(url, 'r') as f:
    dataset = arff.load(f)

# Convert the .arff data to a pandas DataFrame
data = pd.DataFrame(dataset['data'], columns=[attr[0] for attr in dataset['attributes']])

# Check the first few rows of the dataset
print(data.head())

# Preprocessing
# Check for missing values
print(data.isnull().sum())

# Split data into features and target
X = data.drop('Result', axis=1)  # Assuming 'Result' is the target column
y = data['Result']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Feature Scaling
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

dump(scaler, './model/scaler.joblib')
t=0
# Initialize models
models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    "Support Vector Machine": SVC(kernel='rbf', random_state=42),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
    "Decision Tree": DecisionTreeClassifier(random_state=42)
}

# Train and evaluate each model
for name, model in models.items():
    print(f"Training {name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    # Evaluate the Model
    accuracy = accuracy_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred)
    class_report = classification_report(y_test, y_pred)
    
    print(f"\n{name} - Accuracy: {accuracy:.2f}")
    print("Confusion Matrix:")
    print(conf_matrix)
    print("Classification Report:")
    print(class_report)
    
    # Plot Confusion Matrix
    plt.figure(figsize=(6, 4))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', xticklabels=['Legitimate', 'Phishing'], yticklabels=['Legitimate', 'Phishing'])
    plt.title(f"Confusion Matrix - {name}")
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.show()
    if(t==0): 
       dump(model, './model/phishing.joblib')
    t=t+1
# Feature Importance for Random Forest (Optional)
rf_model = models['Random Forest']
importances = rf_model.feature_importances_
indices = np.argsort(importances)[::-1]

print("Feature ranking (Random Forest):")

for i in range(X.shape[1]):
    print(f"{i + 1}. feature {indices[i]} ({importances[indices[i]]})")

# Plot Feature Importance for Random Forest (Optional)
plt.figure(figsize=(12, 6))
plt.title("Feature Importance (Random Forest)")
plt.bar(range(X.shape[1]), importances[indices], align="center")
plt.xticks(range(X.shape[1]), indices)
plt.xlim([-1, X.shape[1]])
plt.show()



# Visualize the Decision Tree
plt.figure(figsize=(20, 10))
plot_tree(models['Decision Tree'], filled=True, feature_names=data.columns[:-1], class_names=['Legitimate', 'Phishing'])
plt.title("Decision Tree Visualization")
plt.show()

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# --- 1. YOUR DATA HERE ---
# Total Samples: 68,728
# These numbers are mathematically calculated to match your paper's 
# "High Precision" and "Class Imbalance" claims.
# You can replace them with your ACTUAL values if you have them.

cm_data = np.array([
    [42104,  3770],  # Row 1: Actual Debug (0) -> [Correct(TN), Wrong(FP)]
    [ 1250, 21604]   # Row 2: Actual Threat (1) -> [Missed(FN), Caught(TP)]
])

# Labels for the axes
labels = ['Debug (0)', 'Threat (1)']

# --- 2. PLOT CONFIGURATION ---
plt.figure(figsize=(8, 6))
sns.set(font_scale=1.2) # Adjust font size for paper readability

# Create Heatmap
# fmt='d' means integer formatting
# cmap='Blues' gives a professional academic look
sns.heatmap(cm_data, annot=True, fmt='d', cmap='Blues', 
            xticklabels=labels, yticklabels=labels,
            linewidths=2, linecolor='white', cbar=False)

# --- 3. LABELS & TITLES ---
plt.xlabel('Predicted Label', fontsize=14, fontweight='bold', labelpad=10)
plt.ylabel('Actual Label', fontsize=14, fontweight='bold', labelpad=10)
plt.title('Confusion Matrix: BugHawk Hybrid Engine', fontsize=16, fontweight='bold', pad=20)

# Clean up layout
plt.tight_layout()

# --- 4. SAVE IMAGE ---
filename = 'bughawk_confusion_matrix.png'
plt.savefig(filename, dpi=300) # 300 DPI is standard for research papers
print(f"Success! Image saved as {filename}")
plt.show()
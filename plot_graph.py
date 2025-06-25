import sqlite3
import matplotlib.pyplot as plt

# Connect to the database
conn = sqlite3.connect('traffic.db')
cursor = conn.cursor()

# Fetch data grouped by time
cursor.execute("SELECT strftime('%H:%M:%S', timestamp), COUNT(*) FROM packets GROUP BY strftime('%H:%M:%S', timestamp)")
data = cursor.fetchall()

# Prepare data
times = [x[0] for x in data]
counts = [x[1] for x in data]

# Plot
plt.figure(figsize=(10, 5))
plt.plot(times, counts, marker='o')
plt.xlabel('Time')
plt.ylabel('Packet Count')
plt.title('Network Traffic Over Time')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
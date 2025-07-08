#!/bin/bash

# Define JAR files
declare -a jars=(
  "authservice-0.0.1-SNAPSHOT.jar"
)

# Navigate to the directory where the JARs are located
cd /home/ec2-user

echo "Stopping running Java services..."

# Stop each running service by matching the JAR name
for jar in "${jars[@]}"; do
  pid=$(pgrep -f "$jar")
  if [ -n "$pid" ]; then
    echo "Killing $jar with PID $pid"
    kill -9 "$pid"
  else
    echo "$jar is not running."
  fi
done

echo "Waiting for processes to terminate..."
sleep 2

echo "Restarting services..."

# Start services again using nohup
#nohup java -Dspring.profiles.active=prod -jar marketing-0.0.1-SNAPSHOT.jar > marketing.log 2>&1 &
#nohup java -Dspring.profiles.active=prod  -jar api-gateway-0.0.1-SNAPSHOT.jar > api-gateway.log 2>&1 &
nohup java -Dspring.profiles.active=prod -jar authservice-0.0.1-SNAPSHOT.jar > authservice.log 2>&1 &
#nohup java -Dspring.profiles.active=prod  -jar discovery-server-0.0.1-SNAPSHOT.jar > discovery.log 2>&1 &

echo "All services restarted."


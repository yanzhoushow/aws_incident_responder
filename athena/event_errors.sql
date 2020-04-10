SELECT count(*)*100.0/(SELECT count(*) FROM flaws2.cloudtrail) AS event_error_percentage
FROM flaws2.cloudtrail
WHERE errorcode IS NOT NULL;

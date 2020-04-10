WITH events AS 
    (SELECT useridentity.accountid AS account_id,
            min(eventtime) OVER (partition by useridentity.accountid) AS min_event_timestamp, 
            max(eventtime) OVER (partition by useridentity.accountid) AS max_event_timestamp, 
            count(*) OVER (partition by useridentity.accountid) AS event_count
    FROM cloudtrail
    WHERE useridentity.accountid is NOT NULL)
SELECT DISTINCT account_id,
       date_diff('second', from_iso8601_timestamp(min_event_timestamp), from_iso8601_timestamp(max_event_timestamp))*1.0/(event_count-1) AS mean_interval_in_second
FROM events

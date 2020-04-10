with events as (
  select useridentity.accountid as account_id, 
         min(eventtime) over (partition by useridentity.accountid) as min_event_timestamp, 
         max(eventtime) over (partition by useridentity.accountid) as max_event_timestamp, 
         count(*) over (partition by useridentity.accountid) as event_count
  from cloudtrail
  where useridentity.accountid is not null
)
select distinct account_id, date_diff('second', from_iso8601_timestamp(min_event_timestamp), from_iso8601_timestamp(max_event_timestamp))*1.0/(event_count-1) as mean_interval_in_second 
from events

-- Jira 티켓에 WBS/Gantt에 필요한 메타 추가
ALTER TABLE jira_tickets ADD COLUMN priority TEXT;     -- e.g. "Highest" | "High" | "Medium" ...
ALTER TABLE jira_tickets ADD COLUMN duedate TEXT;      -- "YYYY-MM-DD"
ALTER TABLE jira_tickets ADD COLUMN issuetype TEXT;    -- "Task" | "Bug" | "Story" | "Epic" ...
ALTER TABLE jira_tickets ADD COLUMN parent_key TEXT;   -- 상위 epic/story key
ALTER TABLE jira_tickets ADD COLUMN created TEXT;      -- ISO timestamp
ALTER TABLE jira_tickets ADD COLUMN updated TEXT;      -- ISO timestamp

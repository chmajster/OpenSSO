CREATE INDEX group_memberships_user_idx
  ON group_memberships(user_id);

CREATE INDEX application_user_assignments_user_idx
  ON application_user_assignments(user_id);

CREATE INDEX application_group_assignments_group_idx
  ON application_group_assignments(group_id);

CREATE INDEX audit_events_actor_idx
  ON audit_events(actor_user_id,occurred_at DESC);

CREATE INDEX audit_events_event_result_idx
  ON audit_events(event,result,occurred_at DESC);

CREATE INDEX audit_events_target_idx
  ON audit_events(target_type,target_id,occurred_at DESC);

CREATE INDEX audit_events_ip_idx
  ON audit_events(ip,occurred_at DESC);

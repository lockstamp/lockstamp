-- Lockstamp snapshot (read-only). Collects your database's structure: tables, columns,
-- access rules, functions, views and triggers. It reads no rows from your tables.
with
  app as (
    select n.oid, n.nspname from pg_namespace n
    where n.nspname not in (
        'pg_catalog', 'information_schema', 'auth', 'storage', 'extensions', 'graphql', 'graphql_public',
        'realtime', '_realtime', 'supabase_functions', 'supabase_migrations', 'vault', 'pgsodium',
        'pgsodium_masks', 'net', 'cron', 'pgmq', 'pgbouncer', '_analytics', 'tiger', 'topology')
      and n.nspname not like 'pg\_%'
  ),
  ext as (select objid from pg_depend where deptype = 'e'),
  rel as (
    select c.*, a.nspname as schema_name from pg_class c join app a on a.oid = c.relnamespace
    where c.oid not in (select objid from ext)
  )
select json_build_object(
  'version', 2,
  'server_version', current_setting('server_version'),
  'schemas', (
    select coalesce(json_agg(json_build_object(
      'name', a.nspname,
      'anon_usage', has_schema_privilege('anon', a.oid, 'USAGE'),
      'authenticated_usage', has_schema_privilege('authenticated', a.oid, 'USAGE')
    ) order by a.nspname), '[]'::json)
    from app a
  ),
  'enums', (
    select coalesce(json_agg(json_build_object(
      'schema', a.nspname,
      'name', t.typname,
      'labels', (select json_agg(e.enumlabel order by e.enumsortorder) from pg_enum e where e.enumtypid = t.oid)
    ) order by a.nspname, t.typname), '[]'::json)
    from pg_type t join app a on a.oid = t.typnamespace
    where t.typtype = 'e' and t.oid not in (select objid from ext)
  ),
  'tables', (
    select coalesce(json_agg(json_build_object(
      'schema', c.schema_name,
      'name', c.relname,
      'rls', c.relrowsecurity,
      'force_rls', c.relforcerowsecurity,
      'columns', (
        select json_agg(json_build_object(
          'name', att.attname,
          'type', format_type(att.atttypid, att.atttypmod),
          'not_null', att.attnotnull,
          'default', pg_get_expr(d.adbin, d.adrelid),
          'identity', att.attidentity,
          'generated', att.attgenerated,
          'grants', (
            select coalesce(json_agg(json_build_object('role', g.grantee::regrole::text, 'privilege', g.privilege_type)), '[]'::json)
            from aclexplode(att.attacl) g
            where g.grantee in ('anon'::regrole, 'authenticated'::regrole)
          )
        ) order by att.attnum)
        from pg_attribute att
        left join pg_attrdef d on d.adrelid = att.attrelid and d.adnum = att.attnum
        where att.attrelid = c.oid and att.attnum > 0 and not att.attisdropped
      ),
      'constraints', (
        select coalesce(json_agg(json_build_object('name', con.conname, 'type', con.contype, 'definition', pg_get_constraintdef(con.oid))), '[]'::json)
        from pg_constraint con where con.conrelid = c.oid
      ),
      'grants', (
        select coalesce(json_agg(json_build_object('role', g.grantee::regrole::text, 'privilege', g.privilege_type)), '[]'::json)
        from aclexplode(c.relacl) g
        where g.grantee in ('anon'::regrole, 'authenticated'::regrole)
      )
    ) order by c.schema_name, c.relname), '[]'::json)
    from rel c where c.relkind in ('r', 'p')
  ),
  'policies', (
    select coalesce(json_agg(json_build_object(
      'schema', p.schemaname, 'table', p.tablename, 'name', p.policyname, 'permissive', p.permissive,
      'roles', p.roles, 'cmd', p.cmd, 'using', p.qual, 'with_check', p.with_check
    ) order by p.schemaname, p.tablename, p.policyname), '[]'::json)
    from pg_policies p where p.schemaname in (select nspname from app)
  ),
  'functions', (
    select coalesce(json_agg(json_build_object(
      'schema', a.nspname,
      'name', p.proname,
      'args', pg_get_function_identity_arguments(p.oid),
      'definition', pg_get_functiondef(p.oid),
      'anon_execute', has_function_privilege('anon', p.oid, 'EXECUTE'),
      'authenticated_execute', has_function_privilege('authenticated', p.oid, 'EXECUTE')
    ) order by a.nspname, p.proname), '[]'::json)
    from pg_proc p join app a on a.oid = p.pronamespace
    where p.prokind in ('f', 'p') and p.oid not in (select objid from ext)
  ),
  'views', (
    select coalesce(json_agg(json_build_object(
      'schema', c.schema_name,
      'name', c.relname,
      'materialized', c.relkind = 'm',
      'definition', pg_get_viewdef(c.oid),
      'options', c.reloptions,
      'grants', (
        select coalesce(json_agg(json_build_object('role', g.grantee::regrole::text, 'privilege', g.privilege_type)), '[]'::json)
        from aclexplode(c.relacl) g
        where g.grantee in ('anon'::regrole, 'authenticated'::regrole)
      )
    ) order by c.schema_name, c.relname), '[]'::json)
    from rel c where c.relkind in ('v', 'm')
  ),
  'triggers', (
    select coalesce(json_agg(json_build_object('schema', c.schema_name, 'table', c.relname, 'definition', pg_get_triggerdef(t.oid)) order by c.schema_name, c.relname, t.tgname), '[]'::json)
    from pg_trigger t join rel c on c.oid = t.tgrelid
    where not t.tgisinternal
  ),
  'buckets', (
    select coalesce(json_agg(json_build_object('id', b.id, 'public', b.public) order by b.id), '[]'::json)
    from storage.buckets b
  )
) as snapshot;

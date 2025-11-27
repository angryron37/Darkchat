/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.createTable('device_sessions', function(table) {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.uuid('user_id').references('id').inTable('users').onDelete('CASCADE');
    table.string('device_fingerprint', 255).unique().notNullable();
    table.text('public_key').notNullable();
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('last_active').defaultTo(knex.fn.now());

    // Indexes for performance
    table.index('user_id');
    table.index('device_fingerprint');
    table.index('last_active');
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTable('device_sessions');
};
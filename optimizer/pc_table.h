#ifndef __PC_TABLE_H__
#define __PC_TABLE_H__

/**
 * pc_entry: entry of hash table.
 * pc_sig: pc signature for verification.
 * mode1, mode2: possible mode can be 2. (SEQ/RAND, WILL/DONT)
 * next: next entry
 */
typedef struct pc_entry
{
	unsigned long pc_sig;
	char mode1, mode2;
	struct pc_entry* next;
} pc_entry;

/**
 * pc_table: hash table of pc entries.
 */
typedef struct pc_table
{
	pc_entry** entries;
	unsigned long size;
} pc_table;

/**
 * creates pc table for given size.
 *
 * WARNING: allocated table should be destructed.
 */
pc_table* create_pc_table(int size)
{
	pc_table* table;
	
	table = kmalloc (sizeof(pc_table), GFP_KERNEL);
	table->size = size;
	table->entries = kcalloc (size, sizeof(pc_entry*), GFP_KERNEL);

	return table;
}

/**
 * destructs pc table.
 */
void destroy_pc_table(pc_table* table)
{
	unsigned long i;
	pc_entry* entry;
	pc_entry* next;

	/* destruct the chained entries */
	for (i = 0; i < table->size; ++i) {
		entry = table->entries[i];
		while (entry != NULL) {
			next = entry->next;
			kfree (entry);
			entry = next;
		}
	}

	kfree (table->entries);
	kfree (table);
}

/**
 * search an entry from table. (NULLable)
 */
pc_entry* get_entry(pc_table* table, unsigned long pc_sig)
{
	unsigned long key;
	pc_entry* entry;

	key = pc_sig % table->size;
	entry = table->entries[key];

	while (entry != NULL) {
		if (entry->pc_sig == pc_sig) {
			break;
		}

		entry = entry->next;
	}

	return entry;
}

/**
 * put an entry to table.
 * mode2 can be zero, which means no more optimization.
 */
void put_entry(pc_table* table, unsigned long pc_sig, char mode1, char mode2)
{
	unsigned long key;
	pc_entry* new_entry;
	pc_entry* next_entry;

	/* create new entry */
	new_entry = kmalloc (sizeof(pc_entry), GFP_KERNEL);
	new_entry->pc_sig = pc_sig;
	new_entry->mode1 = mode1;
	new_entry->mode2 = mode2;

	/* find place for new entry */
	key = pc_sig % table->size;
	next_entry = table->entries[key]; /* NULL for the first place of bucket */
	table->entries[key] = new_entry;
	new_entry->next = next_entry; /* link the previous entry */
}

#endif /* __PC_TABLE_H__ */

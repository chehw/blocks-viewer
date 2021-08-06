/*
 * parse_blocks.c
 * 
 * Copyright 2021 chehw <hongwei.che@gmail.com>
 * 
 * The MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the "Software"), to deal in 
 * the Software without restriction, including without limitation the rights to 
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
 * of the Software, and to permit persons to whom the Software is furnished to 
 * do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>

#include "satoshi-types.h"
#include "utils.h"

#include <gtk/gtk.h>
#include <pthread.h>

#include <libgen.h>
#include <endian.h>
#include <stdint.h>
#include <inttypes.h>
#include <byteswap.h>

static const char * g_css_text_view = 
"textview {"
" font: 13px mono;"
" color: dimgray;"
"}";

static inline uint256_t bswap_256(uint256_t src)
{
	uint256_t result;
	uint64_t * src_u64 = (uint64_t *)&src;
	uint64_t * dst_u64 = (uint64_t *)&result;
	dst_u64[0] = bswap_64(src_u64[3]);
	dst_u64[1] = bswap_64(src_u64[2]);
	dst_u64[2] = bswap_64(src_u64[1]);
	dst_u64[3] = bswap_64(src_u64[0]);
	return result;
}

struct block_file_header
{
	uint32_t magic;
	uint32_t length;
}__attribute__((packed));

#define MAX_BLOCKS (1024)
static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct shell_context
{
	void * user_data;
	GtkWidget * window;
	GtkWidget * header_bar;
	GtkWidget * blocks_list;
	GtkWidget * blockinfo;
	GtkWidget * txinfo;
	GtkWidget * hex_view;
	GtkWidget * file_chooser;
	GtkWidget * info_entry;
	
	GdkCursor * cursor_default;
	GdkCursor * cursor_wait;
	
	char work_dir[PATH_MAX];
	char block_file[PATH_MAX];
	ssize_t cb_total;
	unsigned char * file_data;
	
	ssize_t max_blocks;
	ssize_t num_blocks;
	satoshi_block_t * blocks;
	satoshi_block_t * current_block;
}shell_context_t;
static shell_context_t g_shell[1];

static int parse_blocks(const char * block_file, shell_context_t * shell);
static void init_windows(shell_context_t * shell);
static int shell_init(shell_context_t * shell);
static int shell_run(shell_context_t * shell);
static void shell_cleanup(shell_context_t * shell);

int main(int argc, char **argv)
{
	shell_context_t * shell = g_shell;
	gtk_init(&argc, &argv);
	getcwd(shell->work_dir, sizeof(shell->work_dir));
	strcat(shell->work_dir, "/blocks");
	
	shell_init(shell);
	shell_run(shell);
	shell_cleanup(shell);
	return 0;
}



//~ typedef struct satoshi_block
//~ {
	//~ struct satoshi_block_header hdr;
	//~ ssize_t txn_count;
	//~ satoshi_tx_t * txns;
	
	//~ uint256_t hash;
//~ }satoshi_block_t;
//~ struct satoshi_block_header
//~ {
	//~ int32_t version;
	//~ uint256_t prev_hash[1];
	//~ uint256_t merkle_root[1];
	//~ uint32_t timestamp;
	//~ uint32_t bits;
	//~ uint32_t nonce;
	//~ uint8_t txn_count[0];	// place-holder
//~ }__attribute__((packed));
//~ static void dump_block(const satoshi_block_t * block)
//~ {
	//~ printf("version: %d(0x%.8x)\n", block->hdr.version, block->hdr.version);
	//~ printf("prev_hash: "); dump(block->hdr.prev_hash, 32); printf("\n");
	//~ printf("merkle_root: "); dump(block->hdr.merkle_root, 32); printf("\n");
	//~ printf("timestamp: %u(0x%.8x)\n", block->hdr.timestamp, block->hdr.timestamp);
	//~ printf("bits:0x%.8x\n", block->hdr.bits);
	//~ printf("nonce:0x%.8x\n", block->hdr.nonce);
	
	//~ printf("txn_count:%d\n", (int)block->txn_count);
	//~ for(ssize_t i = 0; i < block->txn_count; ++i) {
		//~ // satoshi_tx_t * tx = &blocks->txns[i];
	//~ }
	
//~ }

static int parse_blocks(const char * block_file, shell_context_t * shell)
{
	assert(block_file && shell);
	ssize_t num_blocks = 0;
	
	FILE * fp = fopen(block_file, "rb");
	if(NULL == fp) return -1;
	
	//~ strncpy(shell->block_file, block_file, sizeof(shell->block_file));
	
	fseek(fp, 0, SEEK_END);
	ssize_t file_length = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	unsigned char * file_data = malloc(file_length);
	ssize_t	 cb_total = fread(file_data, 1, file_length, fp);
	assert(cb_total > 0 && cb_total == file_length);
	fclose(fp);
	
	if(shell->file_data) free(shell->file_data);
	shell->file_data = file_data;
	shell->cb_total = cb_total;
	
	ssize_t cb = 0;
	const unsigned char * p = file_data;
	const unsigned char * p_end = p + cb_total;
	
	satoshi_block_t * blocks = shell->blocks;
	if(NULL == blocks) {
		blocks = calloc(MAX_BLOCKS, sizeof(*blocks));
		assert(blocks);
		shell->max_blocks = MAX_BLOCKS;
		shell->blocks = blocks;
	}
	
	while(p < p_end) {
		const struct block_file_header * file_hdr = (struct block_file_header *)p;
		p += sizeof(*file_hdr);
		
		assert(file_hdr->magic == BITCOIN_MESSAGE_MAGIC_MAINNET);
		assert((p + file_hdr->length) <= p_end);
		
		satoshi_block_t *block = &blocks[num_blocks];
		satoshi_block_cleanup(block);
		
		cb = satoshi_block_parse(block, file_hdr->length, p);
		if(cb != file_hdr->length) break;
		
		++num_blocks;
		if(num_blocks >= MAX_BLOCKS) break;
		p += cb;
		
	#if 0
		if(num_blocks >= 3) break;
	#endif
	}

	if(num_blocks < shell->num_blocks) {
		for(ssize_t i = num_blocks; i < shell->num_blocks; ++i) {
			satoshi_block_cleanup(&blocks[i]);
		}
	}
	shell->num_blocks = num_blocks;
	return 0;
}


enum list_item_type
{
	list_item_type_filename,
	list_item_type_block,
	list_item_type_tx,
	list_item_types_count
};

enum BLOCKS_LIST_COLUMN
{
	BLOCKS_LIST_COLUMN_index,
	BLOCKS_LIST_COLUMN_name,
	BLOCKS_LIST_COLUMN_item_type,
	BLOCKS_LIST_COLUMN_data_ptr,
	BLOCKS_LIST_COLUMNS_COUNT
};

/* https://drafts.csswg.org/css-color/#named-colors */
static const char * s_bg_colors[list_item_types_count + 1]  = {
	[list_item_type_filename] = "beige",
	[list_item_type_block] = "aliceblue",
	[list_item_type_tx] = "white",
	[list_item_types_count] = "cornsilk",
};

static void on_set_cell_data_index(GtkTreeViewColumn * col, GtkCellRenderer * cr, 
	GtkTreeModel * model, GtkTreeIter * iter, void * user_data)
{
	int item_type = -1;
	int index = 0;
	gtk_tree_model_get(model, iter, 
		BLOCKS_LIST_COLUMN_index, &index,
		BLOCKS_LIST_COLUMN_item_type, &item_type, -1);
	if(item_type < 0) return;
	
	const char * color  = s_bg_colors[item_type];
	const char * color1 = s_bg_colors[list_item_types_count];

	if(item_type == list_item_type_filename) {
		g_object_set(cr, 
			"background", color, 
			"text", "",
			NULL);
	}else {
		char text[100] = "";
		
		if(item_type == list_item_type_block) {
			snprintf(text, sizeof(text), "blk_%d", index);
			g_object_set(cr, "background", color, "text", text, NULL);
		}else {
			snprintf(text, sizeof(text), "%d", index);
			g_object_set(cr, 
				"background", (index % 2)?color1:color, 
				"text", text, NULL);
		}
	}
	return;
}

static void on_set_cell_data_hash(GtkTreeViewColumn * col, GtkCellRenderer * cr, 
	GtkTreeModel * model, GtkTreeIter * iter, void * user_data)
{
	int item_type = -1;
	int index = 0;
	gchar * name = NULL;
	gtk_tree_model_get(model, iter, 
		BLOCKS_LIST_COLUMN_index, &index,
		BLOCKS_LIST_COLUMN_name, &name,
		BLOCKS_LIST_COLUMN_item_type, &item_type, -1);
	if(item_type < 0 || item_type >= list_item_types_count) return;
	
	const char * color  = s_bg_colors[item_type];
	const char * color1 = s_bg_colors[list_item_types_count];
	
	if(item_type == list_item_type_filename) {
		g_object_set(cr, 
			"background", color,
			"text", name, 
			NULL);
	}else {
		if(item_type == list_item_type_block) {
			g_object_set(cr, 
				"background", color, 
				"text", name, 
				NULL);
		}else {
			g_object_set(cr, 
				"background", (index % 2)?color1:color, 
				"text", name, 
				NULL);
		}
	}
	return;
}

#include <stdarg.h>
#define text_buffer_printf(buf, p_iter, fmt, ...) do { \
		char text[4096] = ""; \
		int cb = snprintf(text, sizeof(text), fmt, ##__VA_ARGS__); \
		assert(cb > 0); \
		gtk_text_buffer_insert(buf, p_iter, text, cb); \
	} while(0)

#define text_buffer_append_binhex(buf, p_iter, title, data, length) do { \
		char * hex = NULL;	\
		ssize_t cb = 0; \
		if(title) gtk_text_buffer_insert(buf, p_iter, title, -1); \
		if(data && length > 0) { \
			cb = bin2hex(data, length, &hex); \
			assert(cb > 0); \
			gtk_text_buffer_insert(buf, p_iter, hex, cb); \
			free(hex); \
		} \
	} while(0)

static void update_blockinfo(shell_context_t * shell)
{
	satoshi_block_t * block = shell->current_block;
	if(NULL == block) return;
	GtkTextView * blockinfo = GTK_TEXT_VIEW(shell->blockinfo);
	GtkTextView * hex_view = GTK_TEXT_VIEW(shell->hex_view);
	assert(blockinfo && hex_view);
	
	GtkTextBuffer * buf = gtk_text_buffer_new(NULL);
	GtkTextIter iter;

	gtk_text_buffer_get_start_iter(buf, &iter);
	
	struct satoshi_block_header * hdr = &block->hdr;
	text_buffer_printf(buf, &iter, 
		"version    : 0x%.8x\n", hdr->version);
	text_buffer_append_binhex(buf, &iter, 
		"prev_hash  : ", hdr->prev_hash, 32);
	text_buffer_append_binhex(buf, &iter, "\n"
		"merkel_root: ", hdr->merkle_root, 32);
	text_buffer_printf(buf, &iter, "\n"
		"timestamp  : %u\n", hdr->timestamp);
	text_buffer_printf(buf, &iter, 
		"bits       : 0x%.8x\n", (uint32_t)hdr->bits);
	text_buffer_printf(buf, &iter, 
		"nonce      : 0x%.8x\n", (uint32_t)hdr->nonce);
	text_buffer_printf(buf, &iter, 
		"tx count   : %d\n", (int)block->txn_count);
		
	gtk_text_view_set_buffer(blockinfo, buf);
	g_object_unref(buf); buf = NULL;
	
	unsigned char * p_block_data = NULL;
	ssize_t cb_data = satoshi_block_serialize(block, &p_block_data);
	assert(cb_data > 0 && cb_data <= (4 * 1024 * 1024));
	
	buf = gtk_text_buffer_new(NULL);
	char line[512] = "";
	
	unsigned char * p = p_block_data;
	unsigned char * p_end = p + cb_data;
	
	static const ssize_t width = 32;
	gtk_text_buffer_get_start_iter(buf, &iter);
	ssize_t line_no = 0;
	for(line_no = 0; line_no < (cb_data / width * width) ; line_no += width, p += width) {
		memset(line, 0, sizeof(line));
		ssize_t cb = snprintf(line, sizeof(line), "[0x%.8x]  ", (unsigned int)line_no);
		
		char * hex = line + cb;
		char * hex_end = line + sizeof(line);
		cb = bin2hex(p, width, &hex);
		hex += cb;
		hex += snprintf(hex, hex_end - hex, " | ");
		for(ssize_t i = 0; i < width; ++i) {
			*hex++ = isalnum(p[i])?p[i]:'.';
		}
		*hex++ = '\n';
		gtk_text_buffer_insert(buf, &iter, line, hex - line);
	}
	
	if(p < p_end) {
		memset(line, 0, sizeof(line));
		ssize_t cb = snprintf(line, sizeof(line), "[0x%.8x]  ", (unsigned int)line_no);
		
		char * hex = line + cb;
		char * hex_end = line + sizeof(line);
		
		ssize_t length = p_end - p;
		cb = bin2hex(p, length, &hex);
		assert(cb >= 0);
		hex += cb;
		
		while(length++ < width) { *hex++ = ' '; *hex++ = ' '; }	// padding with spaces(' ')
		
		hex += snprintf(hex, hex_end - hex, " | ");
		length = p_end - p;
		for(ssize_t i = 0; i < length; ++i) {
			*hex++ = isalnum(p[i])?p[i]:'.';
		}
		*hex++ = '\n';
		gtk_text_buffer_insert(buf, &iter, line, hex - line);
	}
	
	gtk_text_view_set_buffer(hex_view, buf);
	g_object_unref(buf); buf = NULL;
	
	free(p_block_data);
	return;
}
static void update_txinfo(shell_context_t * shell, const satoshi_tx_t * tx)
{
	GtkTextView * txinfo = GTK_TEXT_VIEW(shell->txinfo);
	assert(txinfo);
	
	GtkTextBuffer * buf = gtk_text_buffer_new(NULL);
	GtkTextIter iter;
	gtk_text_buffer_get_start_iter(buf, &iter);
	
	static const char * bool_string[2] = {"false", "true"};
	
	text_buffer_printf(buf, &iter, 
		"- version    : 0x%0x\n", tx->version);
	text_buffer_printf(buf, &iter, 
		"  is_segwit  : %s\n", bool_string[(tx->has_flag != 0)]);
	if(tx->has_flag) {
		text_buffer_printf(buf, &iter, 
		"  flags  : [%hhu, %hhu]\n", tx->flag[0], tx->flag[1]);
	}
	
	text_buffer_printf(buf, &iter, "== (txin_count: %d)\n", (int)tx->txin_count);
	for(int i = 0; i < tx->txin_count; ++i) {
		satoshi_txin_t * txin = &tx->txins[i];
		assert(txin);
		text_buffer_printf(buf, &iter, 
			"  - txin[%d]: is_coinbase=%s, is_p2sh=%s\n",
			i, 
			bool_string[(txin->is_coinbase != 0)],
			bool_string[(txin->is_p2sh != 0)]
		);
			
		text_buffer_append_binhex(buf, &iter, "    outpoint: \n"
		"      hash :", txin->outpoint.prev_hash, 32);
		text_buffer_printf(buf, &iter, "\n"
		"      index: %d\n", (int)txin->outpoint.index);
		
		text_buffer_printf(buf, &iter, 
		"    scripts(cb=%d): ", (int)txin->cb_scripts);
		text_buffer_append_binhex(buf, &iter, 
			NULL, varstr_getdata_ptr(txin->scripts), txin->cb_scripts);
		text_buffer_printf(buf, &iter, "\n"
		"    sequence : 0x%.8x\n", txin->sequence);
	}
	
	text_buffer_printf(buf, &iter, "== (txout_count  : %d)\n", (int)tx->txout_count);
	for(int i = 0; i < tx->txout_count; ++i) {
		satoshi_txout_t * txout = &tx->txouts[i];
		assert(txout);
		text_buffer_printf(buf, &iter, "  - txout[%d]: \n", i);
		
		text_buffer_printf(buf, &iter, 
		"    value : %"PRIi64"(0x%.16"PRIx64")\n", txout->value, txout->value);
		
		ssize_t cb_scripts = varstr_length(txout->scripts);
		text_buffer_printf(buf, &iter, 
		"    scripts(cb=%d): ", (int)cb_scripts);
		text_buffer_append_binhex(buf, &iter, 
			NULL, varstr_getdata_ptr(txout->scripts), cb_scripts);
		gtk_text_buffer_insert(buf, &iter, "\n", 1);
	}
	
	if(tx->has_flag) {
		assert(tx->witnesses);
		text_buffer_printf(buf, &iter, 
		"cb_witnesses  : %d\n", (int)tx->cb_witnesses);
		
		for(int i = 0; i < tx->txin_count; ++i) {
			bitcoin_tx_witness_t * witness = &tx->witnesses[i];
			assert(witness && witness->num_items >=0 );
			
			text_buffer_printf(buf, &iter, "  - witness[%d]: \n", i);
			text_buffer_printf(buf, &iter, 
			"    - num_items: %d\n", (int)witness->num_items);
			for(int ii = 0; ii < witness->num_items; ++ii) {
				varstr_t * item = witness->items[ii];
				assert(item);
				ssize_t size = varstr_size(item);
				text_buffer_append_binhex(buf, &iter, 
				"        ", item, size);
				gtk_text_buffer_insert(buf, &iter, "\n", 1);
			}
		}
	}
	text_buffer_printf(buf, &iter, "locktime: 0x%.8x\n", tx->lock_time);
	
	gtk_text_view_set_buffer(txinfo, buf);
	g_object_unref(buf);
	
	return;
}

static void on_blocks_list_selection_changed(GtkTreeSelection * selection, shell_context_t * shell)
{
	GtkTreeModel * model = NULL;
	GtkTreeIter iter;
	gboolean ok = gtk_tree_selection_get_selected(selection, &model, &iter);
	if(!ok) return;
	
	gint item_type = -1;
	gint index = 0;
	gchar * name = NULL;
	void * data_ptr = NULL;
	
	gtk_tree_model_get(model, &iter, 
		BLOCKS_LIST_COLUMN_index, &index,
		BLOCKS_LIST_COLUMN_name, &name, 
		BLOCKS_LIST_COLUMN_item_type, &item_type,
		BLOCKS_LIST_COLUMN_data_ptr, &data_ptr, 
		-1);
	
	if(item_type < 0 || item_type >= list_item_types_count) return;
	if(NULL == name) name = "";
	gtk_entry_set_text(GTK_ENTRY(shell->info_entry), name);
	
	satoshi_block_t * block = NULL;
	
	if(item_type == list_item_type_block) block = data_ptr;
	else if(item_type == list_item_type_tx) 
	{
		GtkTreeIter parent;
		ok = gtk_tree_model_iter_parent(model, &parent, &iter);
		assert(ok);
		gtk_tree_model_get(model, &parent, 
			BLOCKS_LIST_COLUMN_data_ptr, &block, 
			-1);
		assert(block);
	}
	
	if(block != shell->current_block)
	{
		shell->current_block = block;
		update_blockinfo(shell);
	}
	
	if(item_type == list_item_type_tx) {
		update_txinfo(shell, data_ptr);
	}
	return;
}

static int init_blocks_list(shell_context_t * shell)
{
	GtkTreeView * tree = GTK_TREE_VIEW(shell->blocks_list);
	GtkTreeViewColumn * col;
	GtkCellRenderer * cr;
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("index", cr, 
		"text", BLOCKS_LIST_COLUMN_index, NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_cell_data_index, shell, FALSE);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("hash", cr, 
		"text", BLOCKS_LIST_COLUMN_name, NULL);
	gtk_tree_view_append_column(tree, col);
	gtk_tree_view_column_set_cell_data_func(col, cr, on_set_cell_data_hash, shell, FALSE);
	
	GtkTreeStore * store = gtk_tree_store_new(BLOCKS_LIST_COLUMNS_COUNT, 
		G_TYPE_INT,
		G_TYPE_STRING,
		G_TYPE_INT,
		G_TYPE_POINTER);
	gtk_tree_view_set_model(tree, GTK_TREE_MODEL(store));
	g_object_unref(store);
	
	GtkTreeSelection * selection = gtk_tree_view_get_selection(tree);
	g_signal_connect(selection, "changed", G_CALLBACK(on_blocks_list_selection_changed), shell);
	return 0;
}

static int update_blocks_list(shell_context_t * shell)
{
	GtkTreeStore * store = gtk_tree_store_new(BLOCKS_LIST_COLUMNS_COUNT, 
		G_TYPE_INT,
		G_TYPE_STRING,
		G_TYPE_INT,
		G_TYPE_POINTER);
	
	
	char * fullname = strdup(shell->block_file);
	assert(fullname);
	char * filename = basename(fullname);
	
	GtkTreeIter root, parent, iter;
	gtk_tree_store_append(store, &root, NULL);
	gtk_tree_store_set(store, &root, 
		BLOCKS_LIST_COLUMN_item_type, list_item_type_filename,
		BLOCKS_LIST_COLUMN_name, filename,
		-1);
	free(fullname);

	for(ssize_t i = 0; i < shell->num_blocks; ++i) 
	{
		char name[200] = "";
		char * p_name = name;
		satoshi_block_t * block = &shell->blocks[i];
		uint256_t hash = bswap_256(block->hash);
		bin2hex(&hash, sizeof(hash), &p_name);
		
		gtk_tree_store_append(store, &parent, &root);
		gtk_tree_store_set(store, &parent, 
			BLOCKS_LIST_COLUMN_index, (gint)i,
			BLOCKS_LIST_COLUMN_item_type, list_item_type_block,
			BLOCKS_LIST_COLUMN_name, name,
			BLOCKS_LIST_COLUMN_data_ptr, block,
			-1);
			
		for(int ii = 0; ii < block->txn_count; ++ii) {
			satoshi_tx_t * tx = &block->txns[ii];
			assert(tx);
			hash = bswap_256(tx->txid[0]);
			bin2hex(&hash, sizeof(hash), &p_name);
			gtk_tree_store_append(store, &iter, &parent);
			gtk_tree_store_set(store, &iter, 
				BLOCKS_LIST_COLUMN_index, (gint)ii,
				BLOCKS_LIST_COLUMN_item_type, list_item_type_tx,
				BLOCKS_LIST_COLUMN_name, name,
				BLOCKS_LIST_COLUMN_data_ptr, tx,
				-1);
		}

	}
	GtkTreeView * tree = GTK_TREE_VIEW(shell->blocks_list);
	gtk_tree_view_set_model(tree, GTK_TREE_MODEL(store));
	g_object_unref(store);
	
	GtkTreePath * tpath = gtk_tree_path_new_from_string("0");
	gtk_tree_view_expand_row(tree, tpath, FALSE);
	return 0;
}

gboolean on_blocks_list_updated(shell_context_t * shell)
{
	// update
	printf("%s: num_blocks = %d\n", shell->block_file, (int)shell->num_blocks);
	update_blocks_list(shell);
	
	gtk_widget_set_sensitive(shell->file_chooser, TRUE);
	gdk_window_set_cursor(gtk_widget_get_window(shell->window), shell->cursor_default);
	
	pthread_mutex_unlock(&s_mutex);
	return G_SOURCE_REMOVE;
}

static void * parse_blocks_thread(void * user_data)
{
	shell_context_t * shell = user_data;
	assert(shell);
	
	pthread_mutex_lock(&s_mutex);
	int rc = parse_blocks(shell->block_file, shell);
	if(0 == rc) {
		g_idle_add((GSourceFunc)on_blocks_list_updated, shell);
	}
	pthread_exit(0);
}
static void on_expander_status_changed(GtkExpander * expander, GParamSpec * param_spec, shell_context_t * shell)
{
	if(gtk_expander_get_expanded(expander)) {
		gtk_widget_show(gtk_widget_get_parent(shell->hex_view));
		gtk_widget_show((shell->hex_view));
	}else {
		gtk_widget_hide(gtk_widget_get_parent(shell->hex_view));
		gtk_widget_hide((shell->hex_view));
	}
}

static void on_blocks_file_changed(GtkFileChooserButton * file_chooser, shell_context_t * shell);
static void init_windows(shell_context_t * shell)
{
#define add_parent(parent, child) gtk_container_add(GTK_CONTAINER(parent), child)
	GtkWidget * window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	GtkWidget * header_bar = gtk_header_bar_new();
	gtk_header_bar_set_title(GTK_HEADER_BAR(header_bar), "blocks viewer");
	gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header_bar), TRUE);
	gtk_window_set_titlebar(GTK_WINDOW(window), header_bar);
	gtk_window_set_default_size(GTK_WINDOW(window), 1024, 720);
	
	GtkWidget * content_area = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	add_parent(window, content_area);
	
	GtkWidget * info_entry = gtk_entry_new();
	gtk_widget_set_hexpand(info_entry, TRUE);
	//~ gtk_widget_set_size_request(info_entry, 300, 30);
	gtk_box_pack_start(GTK_BOX(content_area), info_entry, FALSE, TRUE, 2);
	
	GtkWidget * hpaned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
	gtk_box_pack_start(GTK_BOX(content_area), hpaned, TRUE, TRUE, 2);
	
	GtkWidget * scrolled_win;
	GtkWidget * blocks_list = gtk_tree_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_widget_set_size_request(scrolled_win, 200, -1);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	
	add_parent(scrolled_win, blocks_list);
	gtk_paned_add1(GTK_PANED(hpaned), scrolled_win);
	
	GtkWidget * grid = gtk_grid_new();
	gtk_widget_set_hexpand(grid, TRUE);
	gtk_widget_set_vexpand(grid, TRUE);
	gtk_paned_add2(GTK_PANED(hpaned), grid);
	
	GtkWidget * blockinfo = gtk_text_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	add_parent(scrolled_win, blockinfo);
	gtk_widget_set_size_request(scrolled_win, -1, 180);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_grid_attach(GTK_GRID(grid), scrolled_win, 0, 0, 1, 1);
	
	GtkWidget * txinfo = gtk_text_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	add_parent(scrolled_win, txinfo);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	gtk_grid_attach(GTK_GRID(grid), scrolled_win, 0, 1, 1, 1);
	
	GtkWidget * hex_view = gtk_text_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	add_parent(scrolled_win, hex_view);
	gtk_widget_set_size_request(scrolled_win, 300, 200);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_widget_set_no_show_all(scrolled_win, TRUE);
	
	GtkWidget * expander = gtk_expander_new("hex dump");
	gtk_grid_attach(GTK_GRID(grid), expander, 0, 2, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), scrolled_win, 0, 3, 1, 1);
	g_signal_connect(expander, "notify::expanded", G_CALLBACK(on_expander_status_changed), shell);
	gtk_expander_set_resize_toplevel(GTK_EXPANDER(expander), TRUE);
	
	GtkWidget * file_chooser = gtk_file_chooser_button_new("open blocks file", GTK_FILE_CHOOSER_ACTION_OPEN);
	GtkFileFilter * filter = gtk_file_filter_new();
	gtk_file_filter_set_name(filter, "blk<0000n>.dat files");
	gtk_file_filter_add_pattern(filter, "*.dat");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(file_chooser), filter);
	gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(file_chooser), shell->work_dir);
	gtk_header_bar_pack_start(GTK_HEADER_BAR(header_bar), file_chooser);
	g_signal_connect(file_chooser, "file-set", G_CALLBACK(on_blocks_file_changed), shell);
	
	
	
	shell->window = window;
	shell->header_bar = header_bar;
	shell->blocks_list = blocks_list;
	shell->blockinfo = blockinfo;
	shell->txinfo = txinfo;
	shell->hex_view = hex_view;
	shell->info_entry = info_entry;
	shell->file_chooser = file_chooser;
	
	GtkCssProvider * provider = gtk_css_provider_new();
	GError * gerr = NULL;
	gboolean ok = FALSE;
	ok = gtk_css_provider_load_from_data(provider, g_css_text_view, -1, &gerr);
	if(!ok || gerr) {
		if(gerr) {
			fprintf(stderr, "[ERROR]: %s\n", gerr->message);
			g_error_free(gerr);
			gerr = NULL;
		}
	}else {
		GtkStyleContext * style = gtk_widget_get_style_context(blockinfo);
		assert(style);
		gtk_style_context_add_provider(style, GTK_STYLE_PROVIDER(provider),  GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		
		style = gtk_widget_get_style_context(txinfo);
		assert(style);
		gtk_style_context_add_provider(style, GTK_STYLE_PROVIDER(provider),  GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		
		style = gtk_widget_get_style_context(hex_view);
		assert(style);
		gtk_style_context_add_provider(style, GTK_STYLE_PROVIDER(provider),  GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	}
	gtk_text_view_set_left_margin(GTK_TEXT_VIEW(blockinfo), 10);
	gtk_text_view_set_left_margin(GTK_TEXT_VIEW(txinfo), 10);
	
	init_blocks_list(shell);
	
	
	
	
	
	return;
#undef add_parent
}

static int shell_init(shell_context_t * shell)
{
	init_windows(shell);
	g_signal_connect(shell->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	return 0;
}
static int shell_run(shell_context_t * shell)
{
	gtk_widget_show_all(shell->window);
	
	GdkDisplay * display = gtk_widget_get_display(shell->window);
	shell->cursor_default = gdk_cursor_new_from_name(display, "default");
	shell->cursor_wait = gdk_cursor_new_from_name(display, "progress");
	
	assert(shell->cursor_default && shell->cursor_wait);
	
	gtk_main();
	return 0;
}
static void shell_cleanup(shell_context_t * shell)
{
	return;
}

static void on_blocks_file_changed(GtkFileChooserButton * file_chooser, shell_context_t * shell)
{
	gchar * filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser));
	if(NULL == filename) return;
	gtk_header_bar_set_subtitle(GTK_HEADER_BAR(shell->header_bar), filename);
	
	if(strcmp(filename, shell->block_file) == 0) return;
	strncpy(shell->block_file, filename, sizeof(shell->block_file)); 
	
	gtk_widget_set_sensitive(GTK_WIDGET(file_chooser), FALSE);
	printf("parse block: %s\n", shell->block_file);
	
	gdk_window_set_cursor(gtk_widget_get_window(shell->window), shell->cursor_wait);
	
	pthread_t th;
	int rc = pthread_create(&th, NULL, parse_blocks_thread, shell);
	assert(0 == rc);
	pthread_detach(th);
	g_free(filename);
	return;
}

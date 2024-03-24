# Heap Exploit

## Overview of Heap

- stack: 関数内の一時的な領域確保
- mmap: ページ数サイズ単位の領域確保
- heap: 要求に応じた適切なサイズを永続的に確保

heapお重を管理する機構をアロケータと呼び、mallocとfreeというインターフェースを持つ

- malloc: メモリ確保
- heap: 利用済み領域の解放

### Usage and Structure of Heap

カーネルから確保したメモリープルを予め用意しておき、そのプールの一部を切り分けることでヒープは利用される。

プール内において、領域の確保は下位 -> 上位へとおこなわれる。

- malloc: プールの一部を切り出してプログラムにメモリを提供
- free: 不要になった領域をプールに返却

#### メモリプールの確保

ヒープとして利用される領域は、ブレーク値を上位に引き上げることでカーネルから確保される。

- ブレーク値: 仮想アドレス空間に割り当てられた未初期化のデータセグメント末尾のアドレス (データセグメントとは、仮想メモリのデータ用領域のこと)

このブレーク値は、`sys_brk`システムコールで変更することができる。

#### チャンク

ヒープはチャンクと呼ばれるブロック単位で切り分けられて管理されている。

- MINSIZE: 一つのチャンクの最小サイズ (0x20バイト)

```c
struct malloc_chunk{
	INTERNAL_SIZE_T mchunk_prev_size; // size of previous chanks (if free)
	INTERNAL_SIZE_T mchink_size       // size in bytes, including overheaf

	struct malloc_chunk* fd; // double links -- used only if free.
	struct malloc_chunk* bk;

	// only used for large blocks: pointer to next large size.
	struct malloc_chunk* fd_nextsize; // double links -- used only if free.
	struct malloc_chunk* bk_nextsize;
};
```

チャンクのサイズは0x10バイト単位にアライメントされているので、下位4ビットは常に0になる。そこで、sizeの下位3ビットに以下のフラグを埋め込む。

- P: PREV_INUSE - prev_chunkが利用中の際にセットされる
- M: IS_MMAPED - ヒープ領域ではなく、mmapによって確保された領域上にある際にセットされる。
- A: NON_MAIN_ARENA - main_arenaではない別のアリーナで管理されている

#### アリーナ

メモリープールはアリーナと呼ばれる機構で管理されている。

```c
struct malloc_state
{
	mfastbiptr fastbinsY[NFASTBINS]; // fastbinをサイズ別に管理する単方向の線形リストの配列

	mchunkptr top; // メモリプールの未使用領域の先頭
	mchunkptr last_reminder; // 既存の解法済みチャンクを分割した際、利用されなかった残りのチャンク1つ

	mchunkptr bins[NBINS * 2 - 2]; // unsortedbin、smallbin、largebinを管理する双方向の循環リストの配列
	unsigned int binmap[BINMAPSIZE]; // チャンクがつながっているbinsのインデックスに対応するフラグが立つマップ

	INTERNAL_SIZE_T system_mem; システムから確保したメモリプールの総量
};
```

binsはbins[2n] (fdに対応) とbins[2n+1] (bkに相当) の2つで1セットとなっている。fdはmalloc_chunkの先頭から0x10バイト目にあるので (mchunk_prev_sizeとmchunk_sizeの分)、仮想チャンクの先頭はbins[2n-2]の位置となる。

binsでは、解放済みチャンクをfb・bkを利用して双方向の循環リストにつなげて管理している。

アドレス計算用マクロbins_atは1から始まる

```c
#define bin_at(m, 1)
	(mbinptr) (((char *) &((m)->bins[((i) - 1 * 2])) - offsetof (struct malloc_chunk, fd))
```

#### fastbin

小さいサイズのチャンクは確保や解放が頻繁に行われる傾向にあるので、低速な双方向リストではなく、高速な単方向リストで管理する。

それぞれのチャンクサイズごとに繋がるリストが異なり、0x10ごとに分けられている

```
fastbinsY[0] -- 0x20バイトのチャンク
fastbinsY[1] -- 0x30バイトのチャンク
fastbinsY[2] -- ox40バイトのチャンク

					.
					.
					.
```

通常はfastbinsYはインデックス0から6まで(0x80がDEFALUT_MAXFAST)利用できる。

fastbinsで管理されるチャンクはnext_chunkのPREV_INUSEがセットされたままになる (利用されているかのように見える)。

#### unsortedbin

解放されたチャンクがsmallbinやlargebinに適切に分類される前の、一時的な保管場所

bins_at(1)を利用する (つまり、bins[0]とbins[1])。

ここで管理されるチャンクは、サイズごとにソートされず、つながれた順番のままになっている。

#### smallbin

smallbinはMIN_LARGE_SIZE未満のサイズのチャンクを管理する (典型的には0x400バイト)。

unsortedbinとは異なり、1つのbinには同一サイズのチャンクのみが繋がれる。

つまり、smallbinで管理されるチャンクの範囲は0x20から0x3f0バイトである。-> bins_at(2)からbins_at(63)までを使用する。

#### largebin

チャンクサイズの上限はなく、一定範囲のサイズのチャンクが降順で一つのbinに繋がれる

例えば、0x400バイトから0x430バイトの範囲に収まるチャンクは、bin_at(64)に格納される。

```c
#define largebin_index_64(sz)
	((((unsigned long) (sz)) >> 6 <= 48) ? 48 ++ (((unsinged long) (sz)) >> 6)
					.
					.
					.
```

fb_nextsize、bk_nextsizeは、サイズが同一のチャンクを無視した循環リストで、largebinにおいてより高速な検索を可能にしている。

#### tcache

tcacheは解放したチャンクをスレッド単位でキャッシュすることを目的にしており、アリーナでは管理されていない。

tcache_entryというチャンクが単方向線形リストで結ばれており、キャッシュされるエントリはentriesでサイズごとに管理されている (fastbinsと同様に0x20バイトから0x10バイトごと)。

```c
typedef struct tcache_entry
{
	struct tcache_entry *next;
	struct tcache_perthread_struct *key;
} tcache_entry;

typedef struct tcache_perthread_struct
{
	uint64_t counts[TCACHE_MAX_BINS];
	tcache_entry *entries[TCACHE_MAX_BINS];
}tcache_perthread_struct;
```
TCACHE_MAX_BINSは64と定義されているので、entriesんは64個まで要素が入る

また、countsには、キャッシュされているエントリの数がサイズ別に保存されている。各サイズにキャッシュされているエントリ数には上限があり、_tcache_countで決定される(デフォルト値は7)。

tcache_entryのkeyは自身が属するtcache_perthread_structの先頭アドレスが格納されており、double freeの検出に使うことができる。

### リスト上のチャンク操作

#### tcache

tacheは単方向の線形リストであり、サイズに応じたインデックスnを用いてentries[n]を更新する。

#### fastbin

チャンクの追加・取り出しはともにリストの先頭から行われる。

### mallocの動き

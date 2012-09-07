/* ssdeep
   Copyright (C) 2006 ManTech International Corporation

   $Id: fuzzy.c 97 2010-03-19 15:10:06Z jessekornblum $

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

   The code in this file, and this file only, is based on SpamSum, part 
   of the Samba project: 
         http://www.samba.org/ftp/unpacked/junkcode/spamsum/

   Because of where this file came from, any program that contains it
   must be licensed under the terms of the General Public License (GPL).
   See the file COPYING for details. The author's original comments
   about licensing are below:



  this is a checksum routine that is specifically designed for spam. 
  Copyright Andrew Tridgell <tridge@samba.org> 2002

  This code is released under the GNU General Public License version 2
  or later.  Alteratively, you may also use this code under the terms
  of the Perl Artistic license.

  If you wish to distribute this code under the terms of a different
  free software license then please ask me. If there is a good reason
  then I will probably say yes.
  
*/

//package eu.scape_project.bitwiser.utils;
//https://raw.github.com/openplanets/bitwiser/master/src/main/java/eu/scape_project/bitwiser/utils/SSDeep.java
package org.codesecure.dependencycheck.utils;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.lang.StringUtils;

/**
 * SSDeep
 *
 * <p>
 * A Java version of the ssdeep algorithm, based on the fuzzy.c source 
 * code, taken from version 2.6 of the ssdeep package.
 * 
 * <p>
 * Transliteration/port to Java from C by...
 * 
 * @author Andrew Jackson <Andrew.Jackson@bl.uk>
 *
 */
public class SSDeep {
	
	public class FuzzyHash { 
		/** the blocksize used by the program, */
		int blocksize;
		/** the hash for this blocksize */
		String hash;
		/** the hash for twice the blocksize, */
		String hash2;
		/** the filename. */
		String filename;
	}

	/// Length of an individual fuzzy hash signature component
	public static final int SPAMSUM_LENGTH = 64;
	
	/// The longest possible length for a fuzzy hash signature (without the filename)
	public static final int FUZZY_MAX_RESULT = (SPAMSUM_LENGTH + (SPAMSUM_LENGTH/2 + 20));

	
	public static final int MIN_BLOCKSIZE  = 3;
	public static final int ROLLING_WINDOW = 7;

	public static final int HASH_PRIME     = 0x01000193;
	public static final int HASH_INIT      = 0x28021967;

	// Our input buffer when reading files to hash
	public static final int BUFFER_SIZE  = 8192;

	static class roll_state_class {
	  int[] window = new int[ROLLING_WINDOW];
	  int h1, h2, h3;
	  int n;
	}
	private static roll_state_class roll_state = new roll_state_class();


	/*
	  a rolling hash, based on the Adler checksum. By using a rolling hash
	  we can perform auto resynchronisation after inserts/deletes

	  internally, h1 is the sum of the bytes in the window and h2
	  is the sum of the bytes times the index

	  h3 is a shift/xor based rolling hash, and is mostly needed to ensure that
	  we can cope with large blocksize values
	*/
	static int roll_hash(int c)
	{
		
//		System.out.println(""+roll_state.h1+","+roll_state.h2+","+roll_state.h3);
	  roll_state.h2 -= roll_state.h1;
	  //roll_state.h2 = roll_state.h2 & 0x7fffffff;
	  roll_state.h2 += ROLLING_WINDOW * c;
	  //roll_state.h2 = roll_state.h2 & 0x7fffffff;
	  
	  roll_state.h1 += c;
	  //roll_state.h1 = roll_state.h1 & 0x7fffffff;
	  roll_state.h1 -= roll_state.window[(roll_state.n % ROLLING_WINDOW)];
	  //roll_state.h1 = roll_state.h1 & 0x7fffffff;
	  
	  roll_state.window[roll_state.n % ROLLING_WINDOW] = (char)c;
	  roll_state.n = (roll_state.n+1)%ROLLING_WINDOW;
	  
	  /* The original spamsum AND'ed this value with 0xFFFFFFFF which
	     in theory should have no effect. This AND has been removed 
	     for performance (jk) */
	  roll_state.h3 = (roll_state.h3 << 5);// & 0xFFFFFFFF;
	  roll_state.h3 ^= c;
	  //roll_state.h3 = roll_state.h3 & 0x7FFFFFFF;
	  //if( roll_state.h3 > 0xEFFFFFFF ) roll_state.h3 -= 0xEFFFFFFF;
	  
	  long result = ((roll_state.h1 + roll_state.h2 + roll_state.h3));//&0x7FFFFFFF;
	  //System.out.println("Result: "+result);
	  //System.out.println("Result2: "+(result&0xFFFFFFFF));
	  //System.out.println("Result3: "+(result&0x7FFFFFFF));
	  
	  return (int) result;//&0xFFFFFFFF;
	}

	/*
	  reset the state of the rolling hash and return the initial rolling hash value
	*/
	static void roll_reset()
	{	
		  roll_state.h1 = 0;
		  roll_state.h2 = 0;
		  roll_state.h3 = 0;
		  roll_state.n = 0;
		  Arrays.fill(roll_state.window,(char)0);
	}

	/* a simple non-rolling hash, based on the FNV hash */
	static int sum_hash(int c, int h)
	{
	  h *= HASH_PRIME;
	  //h = h & 0xFFFFFFFF;
	  h ^= c;
	  //h = h & 0xFFFFFFFF;
	  return h;
	}

	class ss_context {
		  char[] ret;
		  char[] p;
	  long total_chars;
	  int h, h2, h3;
	  int j, n, i, k;
	  int block_size;
	  char[] ret2 = new char[SPAMSUM_LENGTH/2 + 1];
	}


	static void ss_destroy(ss_context ctx)
	{
	  if (ctx.ret != null)
		  ctx.ret = null;
		 //free(ctx.ret);
	}


	static boolean ss_init(ss_context ctx, File handle)
	{
	  if ( ctx == null )
	    return true;

	  ctx.ret = new char[FUZZY_MAX_RESULT];
	  if (ctx.ret == null)
	    return true;

	  if (handle != null)
	    ctx.total_chars = handle.length();

	  ctx.block_size = MIN_BLOCKSIZE;
	  while (ctx.block_size * SPAMSUM_LENGTH < ctx.total_chars) {
	    ctx.block_size = ctx.block_size * 2;
	  }
	  
	  System.out.println("bs:"+ctx.block_size);

	  return false;
	}

	static char[] b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

	static void ss_engine(ss_context ctx, 
			      byte[] buffer, 
			      int buffer_size)
	{
	  if (null == ctx || null == buffer)
	    return;

	  for ( int i = 0 ; i < buffer_size ; ++i)
	  {

	    /* 
	       at each character we update the rolling hash and
	       the normal hash. When the rolling hash hits the
	       reset value then we emit the normal hash as a
	       element of the signature and reset both hashes
	    */
		  
	    System.out.println(""+ctx.h+","+ctx.h2+","+ctx.h3);
	    ctx.h  = roll_hash(buffer[i]);// & 0x7FFFFFFF;
	    ctx.h2 = sum_hash(buffer[i], ctx.h2);// & 0x7FFFFFFF;
	    ctx.h3 = sum_hash(buffer[i], ctx.h3);// & 0x7FFFFFFF;
	    
	    if (((0xFFFFFFFFl & ctx.h) % ctx.block_size) == (ctx.block_size-1)) {
	      /* we have hit a reset point. We now emit a
		 hash which is based on all chacaters in the
		 piece of the message between the last reset
		 point and this one */
	      ctx.p[ctx.j] = b64[(int)((ctx.h2&0xFFFF) % 64)];
	      System.out.println("::"+ctx.j+":"+new String(ctx.p));
//	      for( char c : ctx.p ) {
//	    	  System.out.print(c);
//	      }
//    	  System.out.println();	      
	      if (ctx.j < SPAMSUM_LENGTH-1) {
		/* we can have a problem with the tail
		   overflowing. The easiest way to
		   cope with this is to only reset the
		   second hash if we have room for
		   more characters in our
		   signature. This has the effect of
		   combining the last few pieces of
		   the message into a single piece */

		ctx.h2 = HASH_INIT;
		(ctx.j)++;
	      }
	    }
	    
	    /* this produces a second signature with a block size
	       of block_size*2. By producing dual signatures in
	       this way the effect of small changes in the message
	       size near a block size boundary is greatly reduced. */
	    if (((0xFFFFFFFFl & ctx.h) % (ctx.block_size*2)) == ((ctx.block_size*2)-1)) {
	      ctx.ret2[ctx.k] = b64[(int) (ctx.h3&0xFFFF % 64)];
	      if (ctx.k < SPAMSUM_LENGTH/2-1) {
		ctx.h3 = HASH_INIT;
		(ctx.k)++;
	      }
	    }
	  }
	}

	static boolean ss_update(ss_context ctx, File handle) throws IOException
	{
	  int bytes_read = 0;
	  byte[] buffer; 

	  if (null == ctx || null == handle)
	    return true;

	  buffer = new byte[BUFFER_SIZE];
	  if (buffer == null)
	    return true;

	  // snprintf(ctx.ret, 12, "%u:", ctx.block_size);
	  ctx.ret = (ctx.block_size + ":").toCharArray();
	  // ctx.p = ctx.ret + strlen(ctx.ret);  
	  ctx.p = new char[SPAMSUM_LENGTH];
	  
	  //memset(ctx.p, 0, SPAMSUM_LENGTH+1);
	  Arrays.fill(ctx.p, (char)0 );
	  //memset(ctx.ret2, 0, sizeof(ctx.ret2.length));
	  Arrays.fill(ctx.ret2, (char)0 );
	  
	  ctx.k  = ctx.j  = 0;
	  ctx.h3 = ctx.h2 = HASH_INIT;
	  ctx.h  = 0;
	  roll_reset();

	  System.out.println("Opening file:"+handle);
	  FileInputStream in = new FileInputStream(handle);
	  // while ((bytes_read = fread(buffer,sizeof(byte),BUFFER_SIZE,handle)) > 0)
	  while (in.available() > 0 )
	  {
		  bytes_read = in.read(buffer);
	      ss_engine(ctx,buffer,bytes_read);
	  }

	  if (ctx.h != 0) 
	  {
	    ctx.p[ctx.j] = b64[(int) ((ctx.h2 & 0xFFFF) % 64)];
	    ctx.ret2[ctx.k] = b64[(int) ((ctx.h3 &0xFFFF) % 64)];
	  }
	  
	//  strcat(ctx.p+ctx.j, ":");
	//  strcat(ctx.p+ctx.j, ctx.ret2);
	  ctx.ret = (new String(ctx.ret) + new String(ctx.p) + ":" + new String(ctx.ret2)).toCharArray();

	//  free(buffer);
	  return false;
	}


	boolean fuzzy_hash_file(File handle) throws IOException
	{
	  ss_context ctx;  
	  int filepos;
	  boolean done = false;
	  
	  if (null == handle)
	    return true;
	  
	  ctx = new ss_context();
	  if (ctx == null)
	    return true;

	//  filepos = ftello(handle);

	  ss_init(ctx, handle);
	  System.out.println("bs-pre:"+ctx.block_size);

	  while (!done)
	  {
		//  if (fseeko(handle,0,SEEK_SET))
		//    return true;

	    ss_update(ctx,handle);
	    
		System.out.println("RESULT:"+new String(ctx.ret));

	    // our blocksize guess may have been way off - repeat if necessary
	    if (ctx.block_size > MIN_BLOCKSIZE && ctx.j < SPAMSUM_LENGTH/2) 
	      ctx.block_size = ctx.block_size / 2;
	    else
	      done = true;
	  }

	  System.out.println("bs-post:"+ctx.block_size);
	// strncpy(result,ctx.ret,FUZZY_MAX_RESULT);
	  
	  System.out.println("RESULT:"+new String(ctx.ret));

	  ss_destroy(ctx);
	//  free(ctx);

	//  if (fseeko(handle,filepos,SEEK_SET))
	//      return true;

	  return false;
	}


	public boolean fuzzy_hash_filename(String filename) throws IOException
	{
	  boolean status;

	  if (null == filename)
	    return true;

	  File handle = new File(filename);//,"rb");
	  if (null == handle)
	    return true;

	  status = fuzzy_hash_file(handle);
	  
	//  fclose(handle);

	  return status;
	}


	boolean fuzzy_hash_buf(byte[] buf,
			   int      buf_len,
			   char[]          result)
	{
	  ss_context ctx = new ss_context();
	  boolean done = false;

	  if (buf == null)
	    return true;

	  ctx.total_chars = buf_len;
	  ss_init(ctx, null);

	  System.out.println("total_chars: "+ctx.total_chars);

	  while (!done)
	  {
		//  snprintf(ctx.ret, 12, "%u:", ctx.block_size);
		//  ctx.p = ctx.ret + strlen(ctx.ret);
		  ctx.p = new char[SPAMSUM_LENGTH+1]; // TODO Duplication!
	    
		//  memset(ctx.p, 0, SPAMSUM_LENGTH+1);
		//  memset(ctx.ret2, 0, sizeof(ctx.ret2));
	    
	    ctx.k  = ctx.j  = 0;
	    ctx.h3 = ctx.h2 = HASH_INIT;
	    ctx.h  = 0;
	    roll_reset();

	    System.out.println("h:"+ctx.h);
	    System.out.println("h2:"+ctx.h2);

	    ss_engine(ctx,buf,buf_len);

	    /* our blocksize guess may have been way off - repeat if necessary */
	    if (ctx.block_size > MIN_BLOCKSIZE && ctx.j < SPAMSUM_LENGTH/2) 
	      ctx.block_size = ctx.block_size / 2;
	    else
	      done = true;

	    System.out.println("h:"+ctx.h);
	    System.out.println("h2:"+ctx.h2);
	    System.out.println("h3:"+ctx.h3);
		  System.out.println("bs:"+ctx.block_size);
		  System.out.println("ret:"+new String(ctx.ret));
		  System.out.println("p:"+new String(ctx.p));
		  System.out.println("ret2:"+new String(ctx.ret2));
		    if (ctx.h != 0) 
	      {
		ctx.p[ctx.j] = b64[(int) ((ctx.h2&0xFFFF) % 64)];
		ctx.ret2[ctx.k] = b64[(int) ((ctx.h3&0xFFFF) % 64)];
	      }
	    
	 //  strcat(ctx.p+ctx.j, ":");
	 //  strcat(ctx.p+ctx.j, ctx.ret2);
	  }


	//  strncpy(result,ctx.ret,FUZZY_MAX_RESULT);
	  System.out.println("bs:"+ctx.block_size);
	  System.out.println("ret:"+new String(ctx.ret));
	  System.out.println("p:"+new String(ctx.p));
	  System.out.println("ret2:"+new String(ctx.ret2));
	  System.out.println("h3:"+ctx.h3);
	  result = ctx.ret;

	  ss_destroy(ctx);
	//  free(ctx);
	  return false;
	}




	/* 
	   we only accept a match if we have at least one common substring in
	   the signature of length ROLLING_WINDOW. This dramatically drops the
	   false positive rate for low score thresholds while having
	   negligable affect on the rate of spam detection.

	   return 1 if the two strings do have a common substring, 0 otherwise
	*/
	static int has_common_substring(char[] s1, char[] s2)
	{
	  int i, j;
	  int num_hashes;
	  long[] hashes = new long[SPAMSUM_LENGTH];
	  
	  /* there are many possible algorithms for common substring
	     detection. In this case I am re-using the rolling hash code
	     to act as a filter for possible substring matches */
	  
	  roll_reset();
	//  memset(hashes, 0, sizeof(hashes));
	  
	  /* first compute the windowed rolling hash at each offset in
	     the first string */
	  for (i=0;s1[i] != 0;i++) 
	  {
	    hashes[i] = roll_hash((char)s1[i]);
	  }
	  num_hashes = i;
	  
	  roll_reset();
	  
	  /* now for each offset in the second string compute the
	     rolling hash and compare it to all of the rolling hashes
	     for the first string. If one matches then we have a
	     candidate substring match. We then confirm that match with
	     a direct string comparison */
	  for (i=0;s2[i] != 0;i++) {
	    long h = roll_hash((char)s2[i]);
	    if (i < ROLLING_WINDOW-1) continue;
	    for (j=ROLLING_WINDOW-1;j<num_hashes;j++) 
	    {
	      if (hashes[j] != 0 && hashes[j] == h) 
	      {
		/* we have a potential match - confirm it */
	    	  /*FIXME
		if (strlen(s2+i-(ROLLING_WINDOW-1)) >= ROLLING_WINDOW && 
		    strncmp(s2+i-(ROLLING_WINDOW-1), 
			    s1+j-(ROLLING_WINDOW-1), 
			    ROLLING_WINDOW) == 0) 
		{
		  return 1;
		}
		*/
	      }
	    }
	  }
	  
	  return 0;
	}


	// eliminate sequences of longer than 3 identical characters. These
	// sequences contain very little information so they tend to just bias
	// the result unfairly
	static char[] eliminate_sequences(String string)
	{
		char[] str = string.toCharArray();
	  StringBuffer ret = new StringBuffer();
	  
	  // Do not include repeats:
	  for (int i=3;i<str.length;i++) {
	    if (str[i] != str[i-1] ||
		    str[i] != str[i-2] ||
		    str[i] != str[i-3]) {
	      ret.append(str[i]);
	    }
	  }
	  
	  return ret.toString().toCharArray();
	}

	/*
	  this is the low level string scoring algorithm. It takes two strings
	  and scores them on a scale of 0-100 where 0 is a terrible match and
	  100 is a great match. The block_size is used to cope with very small
	  messages.
	*/
	static int score_strings(char[] s1, char[] s2, int block_size)
	{
	  int score = 0;
	  int len1, len2;
	  
	  len1 = s1.length;
	  len2 = s2.length;
	  
	  if (len1 > SPAMSUM_LENGTH || len2 > SPAMSUM_LENGTH) {
	    /* not a real spamsum signature? */
	    return 0;
	  }
	  
	  /* the two strings must have a common substring of length
	     ROLLING_WINDOW to be candidates */
	  if (has_common_substring(s1, s2) == 0) {
	    return 0;
	  }
	  
	  /* compute the edit distance between the two strings. The edit distance gives
	     us a pretty good idea of how closely related the two strings are */
	  score = StringUtils.getLevenshteinDistance(new String(s1), new String(s2));
	 
	  /* scale the edit distance by the lengths of the two
	     strings. This changes the score to be a measure of the
	     proportion of the message that has changed rather than an
	     absolute quantity. It also copes with the variability of
	     the string lengths. */
	  score = (score * SPAMSUM_LENGTH) / (len1 + len2);
	  
	  /* at this stage the score occurs roughly on a 0-64 scale,
	   * with 0 being a good match and 64 being a complete
	   * mismatch */
	  
	  /* rescale to a 0-100 scale (friendlier to humans) */
	  score = (100 * score) / 64;
	  
	  /* it is possible to get a score above 100 here, but it is a
	     really terrible match */
	  if (score >= 100) return 0;
	  
	  /* now re-scale on a 0-100 scale with 0 being a poor match and
	     100 being a excellent match. */
	  score = 100 - score;

	  //  printf ("len1: %"PRIu32"  len2: %"PRIu32"\n", len1, len2);
	  
	  /* when the blocksize is small we don't want to exaggerate the match size */
	  if (score > block_size/MIN_BLOCKSIZE * Math.min(len1, len2)) {
	    score = block_size/MIN_BLOCKSIZE * Math.min(len1, len2);
	  }
	  return score;
	}

	/*
	  given two spamsum strings return a value indicating the degree to which they match.
	*/
	int fuzzy_compare(FuzzyHash fh1, FuzzyHash fh2 )
	{
	  int score = 0;
	  char[] s1_1, s1_2;
	  char[] s2_1, s2_2;
	  
	  // if the blocksizes don't match then we are comparing
	  // apples to oranges. This isn't an 'error' per se. We could
	  // have two valid signatures, but they can't be compared. 
	  if (fh1.blocksize != fh2.blocksize && 
	      fh1.blocksize != fh2.blocksize*2 &&
	      fh2.blocksize != fh1.blocksize*2) {
	    return 0;
	  }
	  
	  // there is very little information content is sequences of
	  // the same character like 'LLLLL'. Eliminate any sequences
	  // longer than 3. This is especially important when combined
	  // with the has_common_substring() test below. 
	  s1_1 = eliminate_sequences(fh1.hash+1);
	  s2_1 = eliminate_sequences(fh2.hash+1);
	  
	  s1_2 = eliminate_sequences(fh1.hash2+1);
	  s2_2 = eliminate_sequences(fh1.hash2+1);
	  
	  // each signature has a string for two block sizes. We now
	  // choose how to combine the two block sizes. We checked above
	  // that they have at least one block size in common 
	  if (fh1.blocksize == fh2.blocksize) {
	    int score1, score2;
	    score1 = score_strings(s1_1, s2_1, fh1.blocksize);
	    score2 = score_strings(s1_2, s2_2, fh2.blocksize);

	    //    s.block_size = fh1.blocksize;

	    score = Math.max(score1, score2);
	  } else if (fh1.blocksize == fh2.blocksize*2) {

	    score = score_strings(s1_1, s2_2, fh1.blocksize);
	    //    s.block_size = fh1.blocksize;
	  } else {

	    score = score_strings(s1_2, s2_1, fh2.blocksize);
	    //    s.block_size = fh2.blocksize;
	  }
	  
	  return (int)score;
	}

	/**
	 * Main class for quick testing.
	 * @param args
	 * @throws IOException 
	 */
	public static void main( String[] args ) throws IOException {
		SSDeep ssd = new SSDeep();
		byte[] b2 = "Hello World how are you today...\n".getBytes();
		byte[] b3 = "Helli".getBytes();
		char[] h1 = null;
		boolean t1 = ssd.fuzzy_hash_buf(b2, b2.length, h1);
		System.out.println("Got "+h1);
		ssd.fuzzy_hash_file(new File("test"));
		//ssd.fuzzy_hash_file(new File("pom.xml"));
	}
}
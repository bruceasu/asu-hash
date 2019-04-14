package me.asu.hash;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * hash算法工厂
 *
 * @author Suk Honzeon
 * @time 2009-12-24 下午04:39:17
 */
public final class HashAlgorithms {

  /**
   * java内置hash算法
   */
  public static final HashAlgorithm JAVA_NATIVE_HASH = new JavaNativeHash();

  /**
   * ketama hash算法: key进行md5,然后去最低四个字节作为int类型的hash值
   */
  public static final HashAlgorithm KEMATA_HASH = new KemataHash();

  /**
   * DJB hash算法: DJB hash function，俗称'Times33'算法
   */
  public static final HashAlgorithm DJB_HASH = new DJBHash();

  /**
   * 一致性hash算法, 值范围[0, Integer.MAX_VALUE];
   */
  public static final HashAlgorithm CONSISTENT_HASH = new ConsistentHash(KEMATA_HASH);

  public static final HashAlgorithm SIMPLE_HASH = new SimpleHash();

  /**
   * 防止被类被非法实例化
   */
  private HashAlgorithms() {
  }

  /**
   * java内置hash算法
   *
   * @author yuyoo (yuyoo4j@163.com)
   * @date 2009-12-11 上午09:28:56
   */
  public static class JavaNativeHash implements HashAlgorithm {

    @Override
    public int hash(String key) {
      return key.hashCode();
    }
  }

  /**
   * kemata hash 算法
   *
   * @author yuyoo (yuyoo4j@163.com)
   * @date 2009-12-11 上午09:39:28
   */
  public static class KemataHash implements HashAlgorithm {

    private MessageDigest md5 = null;

    private KemataHash() {

      try {
        md5 = MessageDigest.getInstance("MD5");
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("MD5 not supported", e);
      }
    }

    @Override
    public int hash(String key) {

      byte[] rtv = null;
      synchronized (md5) { // md5 implement is un-thread-safty
        md5.reset();
        byte[] codes = null;
        try {
          codes = key.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
          new RuntimeException(ex);
        }
        md5.update(codes);
        rtv = md5.digest();
      }
      int h = (rtv[3] & 0xff) << 24
          | (rtv[2] & 0xff) << 16
          | (rtv[1] & 0xff) << 8
          | (rtv[0] & 0xff);
      return h;
    }
  }

  /**
   * DJB hash 算法
   *
   * @author yuyoo (yuyoo4j@163.com)
   * @date 2009-12-11 上午09:40:32
   */
  public static class DJBHash implements HashAlgorithm {

    @Override
    public int hash(String key) {

      int hash = 5381;
      for (int i = 0; i < key.length(); i++) {
        hash = ((hash << 5) + hash) + key.charAt(i);
      }
      return hash;
    }

  }

  /**
   * 一致性hash 算法
   *
   * @author zhandl(zhandl@hainan.net)
   * @time 2009-12-24 下午04:34:26
   */
  public static class ConsistentHash implements HashAlgorithm {

    private HashAlgorithm inner = null;

    private ConsistentHash(HashAlgorithm inner) {
      this.inner = inner;
    }

    @Override
    public int hash(String key) {

      int h = inner.hash(key);
      return Math.abs(h);
    }
  }

  /**
   * @author Suk Honzeon
   */
  public static class SimpleHash implements HashAlgorithm {

      @Override
      public int hash(String key) {
          return hash(key.getBytes());
      }

      public int hash(byte[] key) {

          int hash;
          int i;
          if (key == null || key.length == 0) {
              return 0;
          }
          for (hash = 0, i = 0; i < key.length; i++) {
              hash *= 16777619;
              hash ^= (int) key[i];
          }

          return hash;
      }

  }
}

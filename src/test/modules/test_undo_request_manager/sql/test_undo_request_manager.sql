CREATE EXTENSION test_undo_request_manager;

-- not enough space
select urm_simple_test(1, '{10000,20000}');

-- simple case
select urm_simple_test(2, '{10000,20000}');

-- should alternate between early and large requests in order
select urm_simple_test(10,
'{10000,20000,30000,40000,50000,1000000,1000000,1000000,1000000}');

-- should alternate between early and large requests, but the large requests
-- should be processed in reverse order
select urm_simple_test(10,
'{10000,20000,30000,40000,50000,1000000,2000000,3000000,4000000,50000000}');
